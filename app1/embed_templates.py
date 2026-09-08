"""Complete visual presets for the embed builder."""


def w(type_, label, inline=False, **extra):
    return {"type": type_, "label": label, "inline": inline, "enabled": True, **extra}


def tpl(id_, name, tagline, accent, title, description, online, offline,
        footer, widgets, **extra):
    base = {
        "id": id_, "name": name, "tagline": tagline, "accent": accent,
        "title": title, "description": description,
        "online": online, "offline": offline, "footer": footer,
        "show_timestamp": True, "accent_bar_width": 4,
        "render_as_description": False, "thumbnail_size": 62,
        "author_enabled": False, "author_name": "", "author_icon_url": "",
        "author_url": "", "author_icon_size": 22,
        "image_enabled": False, "image_url": "", "image_max_height": 0,
        "use_discord_icon": False, "footer_icon_url": "", "widgets": widgets,
    }
    base.update(extra)
    return base


EMBED_TEMPLATES = [
    tpl("emerald-survival", "Emerald Survival", "Survival MOTD and adventurer list", "#22c55e",
        "SURVIVAL WORLD", "A friendly survival world, refreshed live.", "ONLINE", "OFFLINE",
        "Survival network • live",
        [w("motd", "WELCOME TO THE WORLD"), w("status", "WORLD STATUS", True),
         w("players", "ADVENTURERS", True), w("ip", "JOIN ADDRESS", display_style="backtick"),
         w("playerlist", "WHO IS EXPLORING", max_players_in_list=12), w("version", "GAME VERSION", True)],
        use_discord_icon=True),
    tpl("deep-ocean", "Deep Ocean", "Compact network dashboard", "#06b6d4",
        "OCEAN NETWORK", "Clean, compact connection information.", "SAILING", "ANCHORED",
        "Ocean network telemetry",
        [w("status", "NETWORK", True), w("players", "CREW", True), w("version", "VERSION", True),
         w("ip", "CONNECT", display_style="code")], accent_bar_width=6),
    tpl("enderman-violet", "Enderman Violet", "MOTD-first atmospheric layout", "#7c3aed",
        "THE END AWAITS", "Do not look away. The server is watching.", "AWAKE", "LOST IN THE VOID",
        "Transmission from The End",
        [w("motd", "VOID TRANSMISSION", display_style="code"), w("separator", ""), w("status", "DIMENSION", True),
         w("players", "END WALKERS", True), w("ip", "PORTAL COORDINATES", display_style="backtick"),
         w("playerlist", "ENTITIES DETECTED", max_players_in_list=8, playerlist_style="plain")],
        render_as_description=True, author_enabled=True, author_name="End Network", accent_bar_width=7),
    tpl("blaze-flame", "Blaze Flame", "Competitive arena and roster", "#f97316",
        "BLAZE ARENA", "Queue up, gear up, and enter the arena.", "ON FIRE", "COOLING DOWN",
        "Competitive network • live",
        [w("status", "ARENA", True), w("players", "FIGHTERS", True),
         w("playerlist", "CURRENT ROSTER", max_players_in_list=16, playerlist_style="code_numbered"),
         w("ip", "QUEUE SERVER", display_style="code"), w("motd", "MATCH MESSAGE")],
        thumbnail_size=76, accent_bar_width=8),
    tpl("nether-crimson", "Nether Crimson", "Detailed server diagnostics", "#dc2626",
        "NETHER CORE", "Live diagnostics from the Nether gateway.", "CORE ACTIVE", "CORE OFFLINE",
        "Nether operations console",
        [w("status", "CORE", True), w("players", "LOAD", True), w("version", "PROTOCOL", True),
         w("software", "SERVER SOFTWARE", True), w("ip", "GATEWAY", display_style="code"),
         w("motd", "CORE RESPONSE"), w("plugins", "ACTIVE MODULES", max_items=8)],
        author_enabled=True, author_name="Nether Operations", accent_bar_width=7),
    tpl("royal-gold", "Royal Gold", "Kingdom presentation with subjects", "#f59e0b",
        "THE KINGDOM", "The realm welcomes new and returning adventurers.", "GATES OPEN", "GATES CLOSED",
        "By order of the Crown",
        [w("motd", "ROYAL DECREE"), w("status", "CASTLE GATES", True), w("players", "SUBJECTS", True),
         w("ip", "REALM ADDRESS", display_style="backtick"),
         w("playerlist", "COURT ATTENDANCE", max_players_in_list=20), w("version", "REALM VERSION", True)],
        author_enabled=True, author_name="Royal Network", use_discord_icon=True, thumbnail_size=78),
    tpl("slime-lime", "Slime Lime", "Playful minimal status card", "#a3e635",
        "SLIME TIME", "Jump in and see who is bouncing online.", "BOUNCING", "SPLATTED",
        "Boing • updates every minute",
        [w("status", "SLIME STATE", True), w("players", "BOUNCERS", True),
         w("ip", "BOUNCE HERE", display_style="backtick"), w("motd", "SLIME SAYS")],
        render_as_description=True, accent_bar_width=5),
    tpl("sakura-bloom", "Sakura Bloom", "Community message and player list", "#ec4899",
        "SAKURA TOWNS", "Build, trade, and grow with our community.", "BLOOMING", "WINTER REST",
        "Sakura community status",
        [w("motd", "COMMUNITY BOARD"), w("status", "TOWN STATUS", True), w("players", "NEIGHBOURS", True),
         w("playerlist", "IN TOWN NOW", max_players_in_list=20, playerlist_style="plain"),
         w("ip", "VISIT US", display_style="code")],
        author_enabled=True, author_name="Sakura Community", use_discord_icon=True),
    tpl("obsidian-night", "Obsidian Night", "Dense technical monitor", "#64748b",
        "SYSTEM STATUS", "Real-time Minecraft service monitor.", "OPERATIONAL", "UNAVAILABLE",
        "Automated status monitor",
        [w("status", "SERVICE", True), w("players", "USERS", True), w("version", "VERSION", True),
         w("software", "SOFTWARE", True), w("ip", "ENDPOINT", display_style="code"),
         w("retrieved_at", "LAST CHECK", True), w("motd", "RESPONSE")],
        thumbnail_size=48, accent_bar_width=2),
    tpl("warden-teal", "Warden Teal", "Deep-dark sensor readout", "#14b8a6",
        "DEEP DARK", "Signals detected below the ancient city.", "LISTENING", "SILENT",
        "Deep dark sensor array",
        [w("motd", "SCULK SIGNAL", display_style="code"), w("status", "SENSOR", True),
         w("players", "VIBRATIONS", True), w("ip", "ANCIENT ROUTE", display_style="backtick"),
         w("playerlist", "DETECTED PLAYERS", max_players_in_list=10), w("version", "FREQUENCY", True)],
        render_as_description=True, author_enabled=True, author_name="Sculk Sensor", accent_bar_width=9),
]


def all_templates():
    return EMBED_TEMPLATES
