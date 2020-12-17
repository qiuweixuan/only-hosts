use once_cell::sync::OnceCell;
use tokio::sync::Mutex;

#[derive(Debug)]
struct Client; // so this snippet doesn't depend on MongoDB.

static MONGO: OnceCell<Client> = OnceCell::new();
static MONGO_INITIALIZED: OnceCell<Mutex<bool>> = OnceCell::new();

pub async fn get_mongo() -> &'static Client {
    // this is racy, but that's OK: it's just a fast case
    if let Some(v) = MONGO.get() {
        return v;
    }
    // it hasn't been initialized yet, so let's grab the lock & try to
    // initialize it
    let initializing_mutex = MONGO_INITIALIZED.get_or_init(|| Mutex::new(false));

    // this will wait if another task is currently initializing the client
    let mut initialized = initializing_mutex.lock().await;
    // if initialized is true, then someone else initialized it while we waited,
    // and we can just skip this part.
    if !*initialized {
        // no one else has initialized it yet, so

        let client = Client /* async code to initialize client here! */ ;

        MONGO.set(client).expect(
            "no one else should be initializing this \
            as we hold MONGO_INITIALIZED lock",
        );
        *initialized = true;
        drop(initialized);
    }
    MONGO.get().unwrap()
}

#[tokio::main]
async fn main() {
    let client = get_mongo().await;
    println!("got it: {:?}", client);
}
