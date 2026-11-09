defmodule Membrane.FLV.Parser.Test do
  use ExUnit.Case, async: true

  alias Membrane.FLV.{Packet, Parser}

  @moduletag :capture_log

  @audio 8
  @video 9

  @aac_payload <<10::4, 3::2, 1::1, 1::1, 1::8, "aac frame">>
  @avc_payload <<1::4, 7::4, 1::8, 0::24, "avc frame">>

  describe "parse_header/1" do
    test "accepts a regular header" do
      header = <<"FLV", 1, 0b101, 9::32>>
      assert {:ok, _header, "rest"} = Parser.parse_header(header <> "rest")
    end

    test "waits for the whole header when data_offset is reasonable" do
      assert {:error, :not_enough_data} = Parser.parse_header(<<"FLV", 1, 0b101, 20::32, 0, 0>>)
    end

    test "rejects a header with an absurd data_offset instead of buffering it" do
      assert {:error, {:invalid_data_offset, 0xFFFFFFFF}} =
               Parser.parse_header(<<"FLV", 1, 0b101, 0xFFFFFFFF::32>>)

      assert {:error, {:invalid_data_offset, 0}} = Parser.parse_header(<<"FLV", 1, 0b101, 0::32>>)
    end
  end

  describe "parse_body/1" do
    test "parses valid audio and video tags" do
      body = tag(@audio, @aac_payload) <> tag(@video, @avc_payload)

      assert {:ok, [%Packet{codec: :AAC, type: :audio}, %Packet{codec: :H264, type: :video}],
              <<>>} =
               Parser.parse_body(body)
    end

    test "drops audio tags with a reserved sound format" do
      for sound_format <- [9, 12, 13] do
        body = tag(@audio, <<sound_format::4, 3::2, 1::1, 1::1, 1, 2, 3>>)
        assert {:ok, [], <<>>} = Parser.parse_body(body)
      end
    end

    test "drops video tags with a reserved codec id" do
      for codec_id <- [0, 1] ++ Enum.to_list(8..15) do
        body = tag(@video, <<1::4, codec_id::4, 1, 2, 3>>)
        assert {:ok, [], <<>>} = Parser.parse_body(body)
      end
    end

    test "reports legacy unsupported codecs" do
      body = tag(@video, <<1::4, 2::4, 1, 2, 3>>)
      assert {:error, {:unsupported_codec, :sorenson_h263}} = Parser.parse_body(body)
    end

    test "reports unknown enhanced RTMP FourCCs as unsupported codecs" do
      body = tag(@video, <<1::1, 1::3, 1::4, "avc1", 1, 2, 3>>)
      assert {:error, {:unsupported_codec, "avc1"}} = Parser.parse_body(body)
    end

    test "drops hvc1 coded frames too short to carry the composition time" do
      body = tag(@video, <<1::1, 1::3, 1::4, "hvc1", 1>>)
      assert {:ok, [], <<>>} = Parser.parse_body(body)
    end

    test "drops AVC tags too short to carry the packet type and composition time" do
      body = tag(@video, <<1::4, 7::4, 1>>)
      assert {:ok, [], <<>>} = Parser.parse_body(body)
    end

    test "drops tags with an empty payload" do
      assert {:ok, [], <<>>} = Parser.parse_body(tag(@audio, <<>>))
      assert {:ok, [], <<>>} = Parser.parse_body(tag(@video, <<>>))
    end

    test "drops tags of an unknown type" do
      body = tag(3, <<1, 2, 3>>) <> tag(@audio, @aac_payload)
      assert {:ok, [%Packet{codec: :AAC}], <<>>} = Parser.parse_body(body)
    end

    test "reports encrypted tags" do
      <<previous_tag_size::32, _reserved::2, 0::1, rest::bitstring>> = tag(@audio, @aac_payload)
      body = <<previous_tag_size::32, 0::2, 1::1, rest::bitstring>>
      assert {:error, :encrypted_stream} = Parser.parse_body(body)
    end

    test "keeps parsing after a malformed tag" do
      body = tag(@audio, <<9::4, 3::2, 1::1, 1::1, 1, 2, 3>>) <> tag(@audio, @aac_payload)
      assert {:ok, [%Packet{codec: :AAC}], <<>>} = Parser.parse_body(body)
    end

    test "returns the packets parsed before a tag that can't be parsed" do
      unsupported = tag(@video, <<1::4, 2::4, 1, 2, 3>>)
      body = tag(@audio, @aac_payload) <> unsupported

      assert {:ok, [%Packet{codec: :AAC}], ^unsupported} = Parser.parse_body(body)
      assert {:error, {:unsupported_codec, :sorenson_h263}} = Parser.parse_body(unsupported)
    end
  end

  defp tag(type, payload) do
    <<0::32, 0::2, 0::1, type::5, byte_size(payload)::24, 0::24, 0::8, 0::24, payload::binary>>
  end
end
