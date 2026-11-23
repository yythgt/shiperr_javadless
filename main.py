
import asyncio
import base64
import hmac
import ipaddress
import json
import os
import uuid

from pathlib import Path
from urllib.parse import quote
from aiohttp import web, WSMsgType


# ==========================================
# CONFIG
# ==========================================

CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": int(os.getenv("PORT", "57344")),

    "DOMAIN": os.getenv("DOMAIN", "javadless.shiprr.dev"),
    "PUBLIC_PORT": int(os.getenv("PUBLIC_PORT", "443")),
    "TLS": False,

    "WS_PATH": "/vless",

    "PANEL_USER": os.getenv("PANEL_USER", "admin"),
    "PANEL_PASSWORD": os.getenv("PANEL_PASSWORD", "admin"),

    "USERS_FILE": "users.json",

    "MAX_CONNECTIONS": 100,
    "BUFFER_SIZE": 65536,
}


# ==========================================
# USERS
# ==========================================

users = {}
active_connections = set()

connection_semaphore = asyncio.Semaphore(
    CONFIG["MAX_CONNECTIONS"]
)


def save_users():
    Path(CONFIG["USERS_FILE"]).write_text(
        json.dumps(users, indent=2),
        encoding="utf-8"
    )


def load_users():

    global users

    path = Path(CONFIG["USERS_FILE"])

    if path.exists():

        try:
            users = json.loads(
                path.read_text(encoding="utf-8")
            )

        except Exception:
            users = {}

    if not users:

        user_id = str(uuid.uuid4())

        users[user_id] = {
            "name": "User 1",
            "enabled": True
        }

        save_users()


load_users()


# ==========================================
# VLESS CONFIG GENERATOR
# ==========================================

def generate_vless_config(user_id, name):

    domain = CONFIG["DOMAIN"]
    port = CONFIG["PUBLIC_PORT"]

    path = quote(CONFIG["WS_PATH"], safe="")

    security = "tls" if CONFIG["TLS"] else "none"

    params = (
        "encryption=none"
        f"&security={security}"
        "&type=ws"
        f"&host={quote(domain, safe='')}"
        f"&path={path}"
    )

    return (
        f"vless://{user_id}@{domain}:{port}"
        f"?{params}"
        f"#{quote(name, safe='')}"
    )


# ==========================================
# AUTHENTICATION
# ==========================================

@web.middleware
async def auth_middleware(request, handler):

    if request.path in (
        "/health",
        CONFIG["WS_PATH"]
    ):
        return await handler(request)

    auth = request.headers.get(
        "Authorization", ""
    )

    if auth.startswith("Basic "):

        try:

            decoded = base64.b64decode(
                auth[6:]
            ).decode()

            username, password = decoded.split(
                ":", 1
            )

            valid_user = hmac.compare_digest(
                username,
                CONFIG["PANEL_USER"]
            )

            valid_password = hmac.compare_digest(
                password,
                CONFIG["PANEL_PASSWORD"]
            )

            if valid_user and valid_password:
                return await handler(request)

        except Exception:
            pass

    return web.Response(
        status=401,
        text="Authentication required",
        headers={
            "WWW-Authenticate":
            'Basic realm="VLESS Panel"'
        }
    )


# ==========================================
# VLESS HEADER
# ==========================================

def parse_vless_header(data):

    if len(data) < 24:
        raise ValueError("Invalid header")

    version = data[0]

    if version != 0:
        raise ValueError("Invalid version")

    user_id = str(
        uuid.UUID(bytes=data[1:17])
    )

    addon_length = data[17]

    offset = 18 + addon_length

    if len(data) < offset + 4:
        raise ValueError("Incomplete header")

    command = data[offset]

    port = int.from_bytes(
        data[offset + 1:offset + 3],
        "big"
    )

    address_type = data[offset + 3]

    offset += 4

    if command != 1:
        raise ValueError("TCP only")

    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")

    if address_type == 1:

        if len(data) < offset + 4:
            raise ValueError("Invalid IPv4")

        address = str(
            ipaddress.IPv4Address(
                data[offset:offset + 4]
            )
        )

        offset += 4

    elif address_type == 2:

        if len(data) < offset + 1:
            raise ValueError("Invalid domain")

        length = data[offset]

        offset += 1

        if len(data) < offset + length:
            raise ValueError("Invalid domain length")

        address = data[
            offset:offset + length
        ].decode("utf-8")

        offset += length

    elif address_type == 3:

        if len(data) < offset + 16:
            raise ValueError("Invalid IPv6")

        address = str(
            ipaddress.IPv6Address(
                data[offset:offset + 16]
            )
        )

        offset += 16

    else:
        raise ValueError("Invalid address type")

    return user_id, address, port, data[offset:]


# ==========================================
# TCP RELAY
# ==========================================

async def tcp_to_websocket(reader, ws):

    while not ws.closed:

        data = await reader.read(
            CONFIG["BUFFER_SIZE"]
        )

        if not data:
            break

        await ws.send_bytes(data)


async def websocket_to_tcp(ws, writer, initial_data):

    if initial_data:

        writer.write(initial_data)

        await writer.drain()

    async for message in ws:

        if message.type == WSMsgType.BINARY:

            writer.write(message.data)

            await writer.drain()

        elif message.type in (
            WSMsgType.CLOSE,
            WSMsgType.CLOSED,
            WSMsgType.ERROR
        ):
            break


# ==========================================
# VLESS HANDLER
# ==========================================

async def vless_handler(request):

    ws = web.WebSocketResponse(
        heartbeat=30,
        max_msg_size=0
    )

    await ws.prepare(request)

    active_connections.add(ws)

    writer = None
    reader_task = None

    try:

        async with connection_semaphore:

            first_message = await ws.receive(
                timeout=15
            )

            if first_message.type != WSMsgType.BINARY:
                await ws.close()
                return ws

            user_id, address, port, initial_data = (
                parse_vless_header(
                    first_message.data
                )
            )

            user = users.get(user_id)

            if not user or not user.get("enabled"):
                await ws.close()
                return ws

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    port
                ),
                timeout=15
            )

            await ws.send_bytes(
                bytes([first_message.data[0], 0])
            )

            reader_task = asyncio.create_task(
                tcp_to_websocket(reader, ws)
            )

            await websocket_to_tcp(
                ws,
                writer,
                initial_data
            )

            await reader_task

    except asyncio.CancelledError:
        raise

    except Exception as error:

        print(
            "[VLESS ERROR]",
            repr(error)
        )

    finally:

        if reader_task and not reader_task.done():

            reader_task.cancel()

            await asyncio.gather(
                reader_task,
                return_exceptions=True
            )

        if writer:

            writer.close()

            try:
                await writer.wait_closed()
            except Exception:
                pass

        active_connections.discard(ws)

        if not ws.closed:
            await ws.close()

    return ws


# ==========================================
# PANEL HTML
# ==========================================

HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>VLESS Panel</title>

<style>

body {
    background:#101827;
    color:white;
    font-family:Arial;
    padding:20px;
}

.container {
    max-width:950px;
    margin:auto;
}

.card {
    background:#1c293b;
    padding:20px;
    border-radius:12px;
    margin-bottom:18px;
}

input {
    padding:12px;
    border-radius:7px;
    border:0;
    margin:5px;
}

button {
    padding:10px 14px;
    border:0;
    border-radius:7px;
    cursor:pointer;
    background:#2563eb;
    color:white;
    margin:4px;
}

.delete {
    background:#dc2626;
}

.user {
    background:#26364b;
    padding:15px;
    border-radius:8px;
    margin:10px 0;
    overflow-wrap:anywhere;
}

.config {
    background:#101827;
    padding:12px;
    border-radius:7px;
    margin-top:10px;
    font-size:12px;
    overflow-wrap:anywhere;
}

.status {
    color:#22c55e;
}

</style>
</head>

<body>

<div class="container">

<h2>VLESS Management Panel</h2>

<div class="card">

<h3>Create User</h3>

<input id="name" placeholder="Username">

<button onclick="createUser()">
Create VLESS
</button>

</div>

<div class="card">

<h3>Users</h3>

<div id="users">Loading...</div>

</div>

<div class="card">

<h3>Server Information</h3>

<div id="server"></div>

</div>

</div>

<script>

async function api(path,method="GET",body=null){

    const options = {
        method,
        headers:{}
    };

    if(body){

        options.headers["Content-Type"] =
            "application/json";

        options.body = JSON.stringify(body);
    }

    const response = await fetch(path,options);

    if(!response.ok)
        throw new Error(await response.text());

    return response.json();
}


function escapeHtml(value){

    return String(value).replace(
        /[&<>"']/g,
        c => ({
            "&":"&amp;",
            "<":"&lt;",
            ">":"&gt;",
            '"':"&quot;",
            "'":"&#39;"
        }[c])
    );
}


async function refresh(){

    try{

        const data = await api("/api/users");

        document.getElementById("users").innerHTML =
            data.users.map(user => `

            <div class="user">

                <b>${escapeHtml(user.name)}</b>

                <p>UUID: ${escapeHtml(user.id)}</p>

                <p>
                    Status:
                    ${user.enabled ? "Enabled":"Disabled"}
                </p>

                <div class="config">
                    ${escapeHtml(user.config)}
                </div>

                <button onclick="copyText('${user.id}')">
                    Copy UUID
                </button>

                <button onclick="copyText('${escapeHtml(user.config)}')">
                    Copy VLESS
                </button>

                <button onclick="toggleUser(
                    '${user.id}',
                    ${!user.enabled}
                )">
                    ${user.enabled ? "Disable":"Enable"}
                </button>

                <button class="delete"
                    onclick="deleteUser('${user.id}')">
                    Delete
                </button>

            </div>

            `).join("");


        document.getElementById("server").innerHTML = `
            Domain: ${escapeHtml(data.domain)}<br>
            Port: ${data.port}<br>
            WebSocket: ${escapeHtml(data.path)}<br>
            Active connections: ${data.connections}
        `;

    }catch(error){

        document.getElementById("users").innerText =
            error.message;
    }
}


async function createUser(){

    const name =
        document.getElementById("name").value || "User";

    await api(
        "/api/users",
        "POST",
        {name}
    );

    document.getElementById("name").value = "";

    refresh();
}


async function deleteUser(id){

    if(!confirm("Delete user?"))
        return;

    await api(
        "/api/users/" + id,
        "DELETE"
    );

    refresh();
}


async function toggleUser(id,enabled){

    await api(
        "/api/users/" + id,
        "PATCH",
        {enabled}
    );

    refresh();
}


async function copyText(value){

    await navigator.clipboard.writeText(value);

}


refresh();

setInterval(refresh,5000);

</script>

</body>
</html>
"""


# ==========================================
# API
# ==========================================

async def panel(request):

    return web.Response(
        text=HTML,
        content_type="text/html"
    )


async def list_users(request):

    result = []

    for user_id, user in users.items():

        result.append({

            "id": user_id,

            "name": user.get("name", "User"),

            "enabled": user.get("enabled", False),

            "config": generate_vless_config(
                user_id,
                user.get("name", "User")
            )

        })

    return web.json_response({

        "users": result,

        "domain": CONFIG["DOMAIN"],

        "port": CONFIG["PUBLIC_PORT"],

        "path": CONFIG["WS_PATH"],

        "connections": len(active_connections)

    })


async def create_user(request):

    try:
        data = await request.json()
    except Exception:
        data = {}

    name = str(
        data.get("name", "User")
    )[:50]

    user_id = str(uuid.uuid4())

    users[user_id] = {

        "name": name,

        "enabled": True

    }

    save_users()

    config = generate_vless_config(
        user_id,
        name
    )

    return web.json_response({

        "id": user_id,

        "name": name,

        "config": config

    })


async def delete_user(request):

    user_id = request.match_info["user_id"]

    if user_id not in users:

        return web.json_response(
            {"error": "User not found"},
            status=404
        )

    del users[user_id]

    save_users()

    return web.json_response({
        "success": True
    })


async def update_user(request):

    user_id = request.match_info["user_id"]

    if user_id not in users:

        return web.json_response(
            {"error": "User not found"},
            status=404
        )

    data = await request.json()

    if "enabled" in data:

        users[user_id]["enabled"] = bool(
            data["enabled"]
        )

    save_users()

    return web.json_response({
        "success": True
    })


async def health(request):

    return web.json_response({

        "status": "ok",

        "engine": "python-vless-ws"

    })


# ==========================================
# APPLICATION
# ==========================================

app = web.Application(

    middlewares=[auth_middleware],

    client_max_size=1024 * 1024

)

app.router.add_get("/", panel)

app.router.add_get("/panel", panel)

app.router.add_get(
    CONFIG["WS_PATH"],
    vless_handler
)

app.router.add_get(
    "/api/users",
    list_users
)

app.router.add_post(
    "/api/users",
    create_user
)

app.router.add_delete(
    "/api/users/{user_id}",
    delete_user
)

app.router.add_patch(
    "/api/users/{user_id}",
    update_user
)

app.router.add_get(
    "/health",
    health
)


# ==========================================
# START SERVER
# ==========================================

async def main():

    runner = web.AppRunner(app)

    await runner.setup()

    site = web.TCPSite(

        runner,

        CONFIG["HOST"],

        CONFIG["PORT"]

    )

    await site.start()

    print("================================")
    print("Python VLESS WebSocket started")
    print("Domain:", CONFIG["DOMAIN"])
    print("Port:", CONFIG["PORT"])
    print("Public port:", CONFIG["PUBLIC_PORT"])
    print("WebSocket:", CONFIG["WS_PATH"])
    print("================================")

    await asyncio.Event().wait()


if __name__ == "__main__":

    try:

        asyncio.run(main())

    except KeyboardInterrupt:

        pass
