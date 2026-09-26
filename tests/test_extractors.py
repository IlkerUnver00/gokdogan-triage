from gokdogan.extractors import extract_config


def test_discord_webhook():
    data = b"config https://discord.com/api/webhooks/123456789/AbC-def_GHI more"
    fields = extract_config(data)
    assert any(f.family == "Discord webhook" and "webhooks/123456789" in f.value for f in fields)


def test_telegram_bot_token():
    data = b"send to bot123456789:AAF-abcDEF_ghiJKLmnoPQRstuVWXyz01234 now"
    fields = extract_config(data)
    assert any(f.family == "Telegram bot" and f.key == "bot_token" for f in fields)


def test_remote_config_host():
    data = b"fetch https://pastebin.com/raw/AbCd1234 stage"
    fields = extract_config(data)
    assert any(f.family == "Remote config / stager" for f in fields)


def test_extracts_from_decoded_strings_not_just_raw():
    # the webhook lives only in a decoded string, not the raw image
    decoded = ["https://discord.com/api/webhooks/999/xyz-token_here"]
    fields = extract_config(b"\x00\x01\x02 nothing here", decoded)
    assert any(f.family == "Discord webhook" for f in fields)


def test_dedup():
    data = b"a https://discord.com/api/webhooks/1/t a https://discord.com/api/webhooks/1/t"
    fields = extract_config(data)
    webhooks = [f for f in fields if f.family == "Discord webhook"]
    assert len(webhooks) == 1


def test_clean_data_extracts_nothing():
    assert extract_config(b"just some harmless ascii text with no config") == []


def test_stager_url_stops_at_binary_bytes():
    # In a real binary the URL is followed by NULs and other data, not spaces.
    blob = (b"xx https://raw.githubusercontent.com/org/app/master/VERSION" + bytes([0])
            + b"none" + bytes([0, 0x43, 0xd0]) + b"shlwapi")
    urls = [f.value for f in extract_config(blob) if f.family == "Remote config / stager"]
    assert urls == ["https://raw.githubusercontent.com/org/app/master/VERSION"]


def test_bare_stager_prefix_is_reported():
    # Loaders keep the host prefix and append the paste id at runtime.
    blob = b"xx https://pastebin.com/raw/" + bytes([0]) + b"k3Jd9sQa" + bytes([0])
    urls = [f.value for f in extract_config(blob) if f.family == "Remote config / stager"]
    assert urls == ["https://pastebin.com/raw/"]


def test_bare_stager_prefix_before_other_binary_bytes():
    for tail in (bytes([1, 2, 3]), bytes([0xE9]) + b"t", bytes([0x7F])):
        blob = b"https://raw.githubusercontent.com/" + tail
        urls = [f.value for f in extract_config(blob) if f.family == "Remote config / stager"]
        assert urls == ["https://raw.githubusercontent.com/"], tail
