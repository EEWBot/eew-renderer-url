pub mod quake_prefecture {
    include!(concat!(env!("OUT_DIR"), "/quake_prefecture_v0.rs"));
}

pub mod tsunami {
    include!(concat!(env!("OUT_DIR"), "/tsunami_v0.rs"));
}

use clap::{Parser, Subcommand};
use dateparser::DateTimeUtc;
use hmac::{Hmac, Mac};
use prost::Message;

type HmacSha1 = Hmac<sha1::Sha1>;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    Encode(Encode),
}

#[derive(Parser, Debug)]
struct Encode {
    #[arg(short, long, default_value = "")]
    prefix: String,

    #[command(subcommand)]
    encoding: Encoding,
}

#[derive(Subcommand, Debug)]
enum Encoding {
    Base32768(Base32768),
    Base65536(Base65536),
}

#[derive(Parser, Debug)]
struct Base32768 {
    #[arg(long, default_value = "")]
    hmac_key: String,

    #[command(subcommand)]
    payload: Payload,
}

#[derive(Parser, Debug)]
struct Base65536 {
    #[arg(long, default_value = "")]
    hmac_key: String,

    #[command(subcommand)]
    payload: Payload,
}

#[derive(Subcommand, Debug)]
enum Payload {
    Tsunami(TsunamiPayload),
    V0(V0Payload),
}

#[derive(Clone, Debug)]
struct Epicenter {
    lat_x10: i32,
    lon_x10: i32,
}

impl std::str::FromStr for Epicenter {
    type Err = String;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let (lat, lon) = src
            .split_once(',')
            .ok_or("Exist ',' in string".to_string())?;

        Ok(Epicenter {
            lat_x10: (lat.parse::<f32>().map_err(|e| e.to_string())? * 10.0) as i32,
            lon_x10: (lon.parse::<f32>().map_err(|e| e.to_string())? * 10.0) as i32,
        })
    }
}

#[derive(Parser, Debug)]
struct V0Payload {
    #[arg(short, long)]
    time: DateTimeUtc,

    #[arg(short, long)]
    epicenter: Option<Epicenter>,

    #[arg(long)]
    one: Vec<u32>,

    #[arg(long)]
    two: Vec<u32>,

    #[arg(long)]
    three: Vec<u32>,

    #[arg(long)]
    four: Vec<u32>,

    #[arg(long)]
    five_minus: Vec<u32>,

    #[arg(long)]
    five_plus: Vec<u32>,

    #[arg(long)]
    six_minus: Vec<u32>,

    #[arg(long)]
    six_plus: Vec<u32>,

    #[arg(long)]
    seven: Vec<u32>,
}

#[derive(Parser, Debug)]
struct TsunamiPayload {
    #[arg(short, long)]
    time: DateTimeUtc,

    #[arg(short, long)]
    epicenter: Option<Epicenter>,

    #[arg(short, long)]
    forecast: Vec<u32>,

    #[arg(short, long)]
    advisory: Vec<u32>,

    #[arg(short, long)]
    warning: Vec<u32>,

    #[arg(short, long)]
    major_warning: Vec<u32>,
}

fn encode(e: &Encode) {
    if let Encoding::Base65536(payload) = &e.encoding {
        let Payload::V0(_) = payload.payload else {
            eprintln!("Unsupported paylod for Base65536 format");
            return;
        };
    }

    let (hmac_key, payload) = match &e.encoding {
        Encoding::Base32768(payload) => (&payload.hmac_key, &payload.payload),
        Encoding::Base65536(payload) => (&payload.hmac_key, &payload.payload),
    };

    let (id, body) = match payload {
        Payload::V0(v0) => (
            0,
            crate::quake_prefecture::QuakePrefectureData {
                time: v0.time.0.timestamp() as u64,
                epicenter: v0.epicenter.clone().map(|epicenter| {
                    crate::quake_prefecture::Epicenter {
                        lat_x10: epicenter.lat_x10,
                        lon_x10: epicenter.lon_x10,
                    }
                }),
                one: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.one.clone(),
                }),
                two: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.two.clone(),
                }),
                three: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.three.clone(),
                }),
                four: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.four.clone(),
                }),
                five_minus: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.five_minus.clone(),
                }),
                five_plus: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.five_plus.clone(),
                }),
                six_minus: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.six_minus.clone(),
                }),
                six_plus: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.six_plus.clone(),
                }),
                seven: Some(crate::quake_prefecture::CodeArray {
                    codes: v0.seven.clone(),
                }),
            }
            .encode_to_vec(),
        ),
        Payload::Tsunami(tsunami) => (
            1,
            crate::tsunami::TsunamiForecastData {
                time: tsunami.time.0.timestamp() as u64,
                epicenter: tsunami
                    .epicenter
                    .clone()
                    .map(|epicenter| crate::tsunami::Epicenter {
                        lat_x10: epicenter.lat_x10,
                        lon_x10: epicenter.lon_x10,
                    }),
                advisory: Some(tsunami::CodeArray {
                    codes: tsunami.advisory.clone(),
                }),
                forecast: Some(tsunami::CodeArray {
                    codes: tsunami.forecast.clone(),
                }),
                warning: Some(tsunami::CodeArray {
                    codes: tsunami.warning.clone(),
                }),
                major_warning: Some(tsunami::CodeArray {
                    codes: tsunami.major_warning.clone(),
                }),
            }
            .encode_to_vec(),
        ),
    };

    let sha1 = {
        let mut mac = HmacSha1::new_from_slice(hmac_key.as_bytes()).unwrap();
        mac.update(&body);
        mac.finalize().into_bytes()
    };

    let mut buffer: Vec<u8> = vec![];

    // Add id
    buffer.push(id);

    // Add non-base65536 marker
    if let Encoding::Base32768(_) = &e.encoding {
        buffer.push(0xFF);
    }

    // Add HMAC
    buffer.extend_from_slice(&*sha1);

    // Add Body
    buffer.extend_from_slice(&body);

    let encoded = match &e.encoding {
        Encoding::Base32768(_) => base32768::encode(&buffer),
        Encoding::Base65536(_) => base65536::encode(&buffer, None),
    };

    println!("{}{encoded}", e.prefix);
}

fn main() {
    let cli = Cli::parse();

    match &cli.mode {
        Mode::Encode(e) => encode(e),
    };
}
