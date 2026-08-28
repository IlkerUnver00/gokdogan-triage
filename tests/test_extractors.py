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
