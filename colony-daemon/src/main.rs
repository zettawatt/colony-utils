use autonomi::{Wallet, Client};
use colonylib::{KeyStore, PodManager, DataStore, Graph};
use dialoguer;
use dirs;
use indicatif;
use jsonwebtoken;
use serde_json;
use tokio;
use tracing::{Level, debug, error, info};
use tracing_subscriber::{filter, prelude::*};

#[tokio::main]
async fn main() {

    // Setup error logging
    let subscriber = tracing_subscriber::registry()
    .with(filter::Targets::new()
        .with_target("colonylib", Level::INFO) // INFO level for colonylib
        .with_target("colony-daemon", Level::DEBUG)      // INFO level for colony-daemon
        .with_default(Level::ERROR))          // ERROR level for other modules
    .with(tracing_subscriber::fmt::layer());

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting colony-daemon");

    // parse input arguments using the clap library
    // arguments:
    // -h, --help          - display help information
    // -p, --port <port>   - port to listen on (default: 3000)
    // -l, --listen <ip>   - IP address range to listen from (default: 127.0.0.1)
    // -d, --data <path>   - path to data directory (defaults to dirs::data_dir()/colony)
    // -pass [pass|file]:<password> - password or file with password to unlock key store (default will prompt the user for a password)
    // -n, --network <network>      - Autonomi network to connect to. Options are 'local', 'alpha', or 'main' (default: main)

    /////////////////////////////////
    // DataStore setup step
    /////////////////////////////////
    
    // If the <data> argument is not given:

        // Create a new DataStore instance with the DataStore::create method()

    // Else:

        // Create a new DataStore instance with the DataStore::from_paths() method using
        // - the <data> path for the data_dir argument
        // - the <data>/pods path for the pods_dir argument
        // - the <data>/pod_refs path for the pod_refs_dir argument
        // - dirs::download_dir() path for the downloads_dir argument

    /////////////////////////////////
    // KeyStore setup step
    /////////////////////////////////

    // check if colonylib is already initialized in the <data> directory by checking if the <data> directory is empty
    // if empty:

        // Prompt the user to enter a BIP39 12 word mnemonic or generate a new one using dialoguer

        // prompt the user for a password using dialoguer

        // ask the user to enter the password again and make sure it matches using dialoguer

        // Use the mnemonic to create a new KeyStore using the KeyStore::from_mnemonic method

        // prompt the user for a valid Ethereum wallet private key

        // call the KeyStore set_wallet_key method to store the private key in the KeyStore

        // Call the KeyStore::to_file() method to write the KeyStore to the DataStore get_keystore_path() method path using the given password

    // if not empty:

        // check if directory is a colonylib data directory by checking for the presence of a DataStore::get_keystore_path() keystore file.
        // If it does not exist, exit with an error
    
        // prompt user for password and attempt to open the KeyStore file with KeyStore::from_file()

        // If unlocked continue, else reprompt for a password
    
    /////////////////////////////////
    // Graph setup step
    /////////////////////////////////

    // Create a new Graph instance like this:
    //let graph_path = data_store.get_graph_path();
    //let graph = &mut Graph::open(&graph_path).unwrap();

    /////////////////////////////////
    // Autonomi Connection step
    /////////////////////////////////
    
    // Connect to the specfied Autonomi network using the init_client function

    // Create a wallet instance from the wallet key in the KeyStore using the KeyStore::get_wallet_key() method

    /////////////////////////////////
    // PodManager setup step
    /////////////////////////////////

    // Create a mutable PodManager instance using the PodManager::new() method

    /////////////////////////////////
    // start REST server
    /////////////////////////////////

    // do the following:
    // - create REST endpoints for all colonylib PodManager public methods
    // - listen on the IP range specified by the --listen argument. I.E. 127.0.0.1 is only this machine, 0.0.0.0 is all network interfaces
    // - listen on the port specified by the --port argument

    // Run as a daemon

    /////////////////////////////////
    // client connections
    /////////////////////////////////
    
    // clien connections require a JWT token for authentication. The JWT token is signed by the server using the server's private key.
    // Use the KeyStore password to create the JWT token.

    // the JWT should expire after 10 minutes of no REST calls. If the JWT expires, the client must request a new one.

}

async fn init_client(environment: String) -> Client {
    match environment.trim() {
        "local" => Client::init_local().await.unwrap(),
        "alpha" => Client::init_alpha().await.unwrap(),
        _ => Client::init().await.unwrap(), // "autonomi"
    }
}
