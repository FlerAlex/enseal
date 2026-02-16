pub mod wormhole;

use std::borrow::Cow;

use magic_wormhole::{AppConfig, AppID};

const ENSEAL_APPID: &str = "enseal.dev/transfer";
const DEFAULT_RENDEZVOUS_URL: &str = "ws://relay.magic-wormhole.io:4000/v1";

/// Default number of words in the wormhole code.
pub const DEFAULT_CODE_WORDS: usize = 2;

/// Build the AppConfig for enseal wormhole connections.
pub fn app_config(relay_url: Option<&str>) -> AppConfig<serde_json::Value> {
    let rendezvous_url: Cow<'static, str> = match relay_url {
        Some(url) => Cow::Owned(url.to_string()),
        None => Cow::Borrowed(DEFAULT_RENDEZVOUS_URL),
    };

    AppConfig {
        id: AppID::new(ENSEAL_APPID),
        rendezvous_url,
        app_version: serde_json::json!({"v": 1}),
    }
}
