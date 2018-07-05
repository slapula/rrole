#[macro_use] extern crate quicli;
extern crate chrono;
extern crate rusoto_core;
extern crate rusoto_sts;

use std::default::Default;
use std::io;
use std::env;
use std::collections::HashMap;
use std::process::Command;
use chrono::prelude::*;
use quicli::prelude::*;

use rusoto_core::Region;
use rusoto_sts::{Sts, StsClient};
use rusoto_sts::{GetCallerIdentityRequest, AssumeRoleRequest};

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(help = "RRole Actions: status, assume, reset")]
    action: String,
    #[structopt(long = "user", short = "u", help = "Username", default_value = "")]
    user: String,
    #[structopt(long = "source", short = "s", help = "Source Account Number", default_value = "")]
    source_acct: String,
    #[structopt(long = "destination", short = "d", help = "Destination Account Number", default_value = "")]
    destination_acct: String,
    #[structopt(long = "role", short = "r", help = "Cross Account IAM Role", default_value = "")]
    role: String,
    #[structopt(long = "mfa", short = "m", help = "MFA Token")]
    mfa: bool,
    #[structopt(flatten)]
    verbosity: Verbosity,
}

main!(|args: Cli, log_level: verbosity| {
    let client = StsClient::simple(Region::UsEast1);

    if args.action == "status" {
        let identity_request: GetCallerIdentityRequest = Default::default();

        match client.get_caller_identity(&identity_request).sync() {
            Ok(output) => {
                println!("account: {}", output.account.unwrap());
                println!("arn: {}", output.arn.unwrap());
                println!("user_id: {}", output.user_id.unwrap());
            }
            Err(error) => {
                println!("Error: {:?}", error);
            }
        }

        match env::var("AWS_SESSION_EXPIRES") {
            Ok(date) => {
                let d1 = Utc::now();
                let d2 = date.parse::<DateTime<Utc>>().unwrap();;
                let duration = d2.signed_duration_since(d1);
                println!("expires: {:?} minutes", duration.num_minutes());
            }
            Err(_) => print!(""),
        }
    }

    if args.action == "assume" {
        println!("Please enter MFA token: ");
        let mut mfa_token = String::new();
        io::stdin().read_line(&mut mfa_token).ok().expect("Failed to read input");
        mfa_token.pop();

        match client.assume_role(&AssumeRoleRequest{
            role_arn: format!("arn:aws:iam::{}:role/{}", args.destination_acct, args.role),
            role_session_name: format!("{}_rusoto_session", args.user),
            serial_number: Some(format!("arn:aws:iam::{}:mfa/{}", args.source_acct, args.user)),
            token_code: Some(mfa_token),
            ..Default::default()
        }).sync() {
            Ok(output) => {
                let creds = output.credentials.unwrap();
                let mut env_vars = HashMap::new();
                env_vars.insert("AWS_ACCESS_KEY_ID", creds.access_key_id);
                env_vars.insert("AWS_SECRET_ACCESS_KEY", creds.secret_access_key);
                env_vars.insert("AWS_SESSION_TOKEN", creds.session_token);
                env_vars.insert("AWS_SESSION_EXPIRES", creds.expiration);
                Command::new("bash").envs(&env_vars).status().expect("sh command failed to start");
            }
            Err(error) => {
                println!("Error: {:?}", error);
            }
        }
    }

    if args.action == "reset" {
        println!("Resetting assumed role variables...");
        Command::new("bash")
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_SESSION_EXPIRES")
            .status().expect("sh command failed to start");
    }
});
