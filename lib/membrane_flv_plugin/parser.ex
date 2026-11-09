defmodule Membrane.FLV.Parser do
  @moduledoc false

  require Membrane.Logger

  alias Membrane.FLV
  alias Membrane.FLV.{Header, Packet}

  # The header itself is 9 bytes long and `data_offset` only exists to allow for future
  # extensions. We don't want to buffer gigabytes of input just because a broken file asks for it.
  @max_data_offset 4096

  @spec parse_header(binary()) :: {:ok, Header.t(), binary()} | {:error, reason :: any()}
  def parse_header(
        <<"FLV", 0x01::8, 0::5, type_flags_audio::1, 0::1, type_flags_video::1, data_offset::32,
          _body::binary>> = data
      )
      when data_offset >= 9 and data_offset <= @max_data_offset do
    case data do
      <<_header::binary-size(^data_offset), rest::binary>> ->
        %Header{
          audio_present?: type_flags_audio == 1,
          video_present?: type_flags_video == 1
        }
        |> then(&{:ok, &1, rest})

      _else ->
        {:error, :not_enough_data}
    end
  end

  def parse_header(data) when byte_size(data) < 9, do: {:error, :not_enough_data}

  def parse_header(
        <<"FLV", 0x01::8, 0::5, _type_flags_audio::1, 0::1, _type_flags_video::1, data_offset::32,
          _body::binary>>
      ),
      do: {:error, {:invalid_data_offset, data_offset}}

  def parse_header(_incorrect_data), do: {:error, :not_a_header}

  @spec parse_body(binary()) ::
          {:ok, packets :: [Packet.t()], rest :: binary()}
          | {:error, :not_enough_data}
          | {:error, :encrypted_stream}
          | {:error, {:unsupported_codec, FLV.video_codec_t() | binary()}}
  def parse_body(data) when byte_size(data) < 15, do: {:error, :not_enough_data}

  def parse_body(<<_head::40, data_size::24, _rest::binary>> = data)
      when byte_size(data) < data_size + 15,
      do: {:error, :not_enough_data}

  # the Filter bit indicates an encrypted tag, which we can't parse
  def parse_body(<<_head::32, _reserved::2, 1::1, _type::5, _rest::binary>>),
    do: {:error, :encrypted_stream}

  # script data - ignoring it and continuing with following TAGs
  def parse_body(
        <<_head::32, _reserved::2, 0::1, 18::5, data_size::24, _timestamp::24,
          _timestamp_extended::8, _stream_id::24, _payload::binary-size(data_size), rest::binary>>
      ),
      do: parse_next([], rest)

  # unknown tag type - ignoring it and continuing with following TAGs
  def parse_body(
        <<_head::32, _reserved::2, 0::1, type::5, data_size::24, _timestamp::24,
          _timestamp_extended::8, _stream_id::24, _payload::binary-size(data_size), rest::binary>>
      )
      when type not in [8, 9] do
    Membrane.Logger.warning("Dropping FLV tag of unknown type #{type}")
    parse_next([], rest)
  end

  # proper TAG
  def parse_body(<<
        _previous_tag_size::32,
        _reserved::2,
        0::1,
        type::5,
        data_size::24,
        timestamp::24,
        timestamp_extended::8,
        stream_id::24,
        payload::binary-size(data_size),
        rest::binary
      >>) do
    type = resolve_type(type)

    case parse_payload(type, payload) do
      {:ok, {type, codec, codec_params, payload}} ->
        dts = parse_timestamp(timestamp, timestamp_extended)
        # if composition time is not set in codec_params, then we assume it's 0
        pts = dts + Map.get(codec_params, :composition_time, 0)

        packet = %Packet{
          pts: pts,
          dts: dts,
          stream_id: stream_id,
          type: type,
          payload: payload,
          codec: codec,
          codec_params: codec_params
        }

        parse_next([packet], rest)

      {:error, {:malformed_tag, reason}} ->
        Membrane.Logger.warning("Dropping malformed FLV #{type} tag: #{inspect(reason)}")
        parse_next([], rest)

      {:error, _reason} = error ->
        error
    end
  end

  def parse_body(_too_little_data), do: {:error, :not_enough_data}

  # Parses the TAGs following the ones already parsed. If the next TAG is incomplete or can't be
  # parsed, the packets parsed so far are returned and the rest is left to be parsed once more
  # data arrives, so that the error is reported for the TAG that caused it.
  defp parse_next(packets, rest) do
    case parse_body(rest) do
      {:ok, next_packets, rest} -> {:ok, packets ++ next_packets, rest}
      {:error, _reason} -> {:ok, packets, rest}
    end
  end

  # AAC
  # Ignore parameters set in the header. They are supposed to be extracted from Audio Specific Config
  defp parse_payload(
         :audio,
         <<10::4, 3::2, _sound_size::1, 1::1, packet_type::8, payload::binary>>
       ) do
    type = if packet_type == 1, do: :audio, else: :audio_config
    {:ok, {type, :AAC, %{}, payload}}
  end

  # reserved sound formats, nothing we could do with them
  defp parse_payload(:audio, <<sound_format::4, _rest::bitstring>>)
       when sound_format in [9, 12, 13] do
    {:error, {:malformed_tag, {:reserved_sound_format, sound_format}}}
  end

  # everything else
  defp parse_payload(:audio, <<
         sound_format::4,
         sound_rate::2,
         _sound_size::1,
         sound_type::1,
         payload::binary
       >>) do
    codec = FLV.index_to_sound_format(sound_format)

    sound_rate =
      case sound_rate do
        0 -> 5_500
        1 -> 11_000
        2 -> 22_050
        3 -> 44_100
      end

    sound_type =
      case sound_type do
        0 -> :mono
        1 -> :stereo
      end

    {:ok, {:audio, codec, %{sound_rate: sound_rate, sound_type: sound_type}, payload}}
  end

  # extended rtmp specification: https://github.com/veovera/enhanced-rtmp
  @keyframe_frame_type 1

  @av1 <<"a", "v", "0", "1">>
  @vp9 <<"v", "p", "0", "9">>
  @hevc <<"h", "v", "c", "1">>
  @ex_video_header <<1::1>>

  @packet_type_sequence_start 0
  @packet_type_coded_frames 1
  # @packet_type_sequence_end 2
  # @packet_type_codec_frames_x 3
  @packet_type_metadata 4
  @packet_type_mp4g2ts_sequence_start 5
  defp parse_payload(:video, <<
         @ex_video_header::bitstring,
         frame_type::3,
         packet_type::4,
         video_four_cc::4-binary,
         payload::binary
       >>) do
    with {:ok, codec} <- ext_video_codec(video_four_cc),
         {:ok, composition_time, payload} <- ext_video_payload(codec, packet_type, payload) do
      type = ext_flv_packet_type(video_four_cc, packet_type)

      {:ok,
       {type, codec,
        %{composition_time: composition_time, key_frame?: frame_type == @keyframe_frame_type},
        payload}}
    end
  end

  # AVC H264
  @keyframe_frame_type 1
  defp parse_payload(:video, <<
         frame_type::4,
         7::4,
         packet_type::8,
         composition_time::24,
         payload::binary
       >>) do
    type = if packet_type == 0, do: :video_config, else: :video

    {:ok,
     {type, :H264,
      %{composition_time: composition_time, key_frame?: frame_type == @keyframe_frame_type},
      payload}}
  end

  # AVC tag too short to carry the AVCPacketType and the composition time
  defp parse_payload(:video, <<_frame_type::4, 7::4, _rest::binary>>) do
    {:error, {:malformed_tag, :avc_tag_too_short}}
  end

  defp parse_payload(:video, <<_frame_type::4, codec::4, _rest::binary>>) when codec in 2..6 do
    vcodec = FLV.index_to_video_codec(codec)
    {:error, {:unsupported_codec, vcodec}}
  end

  # reserved video codec ids
  defp parse_payload(:video, <<_frame_type::4, codec::4, _rest::binary>>) do
    {:error, {:malformed_tag, {:reserved_video_codec, codec}}}
  end

  defp parse_payload(_type, <<>>) do
    {:error, {:malformed_tag, :empty_payload}}
  end

  defp ext_video_codec(@av1), do: {:ok, :AV1}
  defp ext_video_codec(@vp9), do: {:ok, :VP9}
  defp ext_video_codec(@hevc), do: {:ok, :HEVC}
  defp ext_video_codec(four_cc), do: {:error, {:unsupported_codec, four_cc}}

  defp ext_video_payload(
         :HEVC,
         @packet_type_coded_frames,
         <<composition_time::24, payload::binary>>
       ),
       do: {:ok, composition_time, payload}

  defp ext_video_payload(:HEVC, @packet_type_coded_frames, _payload),
    do: {:error, {:malformed_tag, :missing_composition_time}}

  defp ext_video_payload(_codec, _packet_type, payload), do: {:ok, 0, payload}

  defp ext_flv_packet_type(video_four_cc, packet_type) do
    cond do
      packet_type == @packet_type_metadata ->
        # NOTE: payload for this packet type includes AMF encoded metadata
        :video_config

      video_four_cc == @av1 and
          packet_type in [@packet_type_sequence_start, @packet_type_mp4g2ts_sequence_start] ->
        :video_config

      video_four_cc in [@hevc, @vp9] and packet_type == @packet_type_sequence_start ->
        :video_config

      true ->
        :video
    end
  end

  defp resolve_type(8), do: :audio
  defp resolve_type(9), do: :video

  defp parse_timestamp(timestamp, timestamp_extended) do
    import Bitwise
    (timestamp_extended <<< 24) + timestamp
  end
end
