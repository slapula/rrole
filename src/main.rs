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

/// Rust Role (aka rrole) manages AWS cross account role assumption.
///
/// There are three main actions this tool performs: status, assume, and reset.
///
/// status: Returns details about your current credentials. It does not take any options.
///
/// assume: Assumes a cross account role.  This action requires user, source, destination, and role to be set.
///
/// reset: Resets the active role you've assumed. This action also does not take options.
#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(help = "status, assume, reset")]
    action: String,
    /// Required for use with the assume action
    #[structopt(long = "user", short = "u", help = "IAM Username", raw(required_if = r#""action", "assume""# ))]
    user: Option<String>,
    /// Required for use with the assume action
    #[structopt(long = "source", short = "s", help = "Source account number", raw(required_if = r#""action", "assume""# ))]
    source_acct: Option<String>,
    /// Required for use with the assume action
    #[structopt(long = "destination", short = "d", help = "Destination account number", raw(required_if = r#""action", "assume""# ))]
    destination_acct: Option<String>,
    /// Required for use with the assume action
    #[structopt(long = "role", short = "r", help = "Cross account IAM role", raw(required_if = r#""action", "assume""# ))]
    role: Option<String>,
    /// Optional for use with the assume action
    #[structopt(long = "mfa", short = "m", help = "Enable MFA")]
    mfa: bool,
    #[structopt(flatten)]
    verbosity: Verbosity,
}

fn role_assume(c: StsClient,req: AssumeRoleRequest) {
    match c.assume_role(&req).sync() {
        Ok(output) => {
            println!("...role assumed!");
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

main!(|args: Cli, log_level: verbosity| {
    let client = StsClient::simple(Region::UsEast1);

    if args.action == "status" {
        let identity_request: GetCallerIdentityRequest = Default::default();

        match client.get_caller_identity(&identity_request).sync() {
            Ok(output) => {
                println!("account: {}", output.account.unwrap());
                println!("arn: {}", output.arn.unwrap());
                println!("access_id: {}", output.user_id.unwrap());
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
    } else if args.action == "assume" {
        println!("Assuming role...");

        if args.mfa == true {
            println!("Please enter MFA token: ");
            let mut mfa_token = String::new();
            io::stdin().read_line(&mut mfa_token).ok().expect("Failed to read input");
            mfa_token.pop();

            let assume_req = AssumeRoleRequest {
                role_arn: format!("arn:aws:iam::{}:role/{}", args.destination_acct.unwrap(), args.role.unwrap()),
                role_session_name: format!("{}_rusoto_session", args.user.clone().unwrap()),
                serial_number: Some(format!("arn:aws:iam::{}:mfa/{}", args.source_acct.unwrap(), args.user.unwrap())),
                token_code: Some(mfa_token),
                ..Default::default()
            };
            role_assume(client, assume_req)
        } else {
            let assume_req = AssumeRoleRequest {
                role_arn: format!("arn:aws:iam::{}:role/{}", args.destination_acct.unwrap(), args.role.unwrap()),
                role_session_name: format!("{}_rusoto_session", args.user.clone().unwrap()),
                ..Default::default()
            };
            role_assume(client, assume_req)
        }
    } else if args.action == "reset" {
        println!("Resetting assumed role variables...");
        Command::new("bash")
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_SESSION_EXPIRES")
            .status().expect("sh command failed to start");
    } else {
        println!("Invalid action.  Valid actions: status, assume, reset");
    }
});
