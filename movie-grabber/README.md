# movie-grabber

Watches a list of movie titles, searches a set of torrent sites on a schedule for **1080p BluRay or WEB/VOD rips from preferred release groups** (YTS, YIFY, ...), downloads them with **qBittorrent**, files them into your **Plex** library using Plex naming, and **emails you** when each one is ready.

```
movies.txt ──► search (YTS, TPB, any Jackett/Prowlarr site) ──► filter + rank ──► qBittorrent
                                                                                       │
      email  ◄──  Plex refresh  ◄──  "Movie (Year)/Movie (Year).mkv" + subtitles  ◄────┘ finished
```

## How it works

1. **Wanted list.** Each run re-reads `movies.txt` (`Title (Year)` per line), so you can edit it at any time.
2. **Schedule.** Searches run *X times every Y*: `schedule.runs: 4` + `schedule.every: 1d` means a search every 6 hours. Finished downloads are checked separately (default every 5 minutes).
3. **Search.** Every enabled source is queried and the results are pooled:
   - `yts`: the YTS/YIFY JSON API
   - `apibay`: The Pirate Bay's JSON API
   - `torznab`: any indexer in **Jackett** or **Prowlarr** (1337x, TorrentGalaxy, LimeTorrents and hundreds more). This is how you add "any site".
4. **Filter.** A release is accepted only when all of these hold:
   - the title and year match exactly (so *The Matrix Reloaded* never counts as *The Matrix*)
   - the resolution is in `resolutions` (default `1080p`)
   - the source is in `sources`: `bluray` (BluRay/BRRip/BDRip) or `web` (WEB-DL/WEBRip/VOD: AMZN, NF, DSNP, iTunes...)
   - the name contains one of the `preferred_groups` (YTS, YIFY, RARBG...)
   - no `exclude_keywords` appear (CAM, TS, TELESYNC, screener, hardcoded subs, 3D...)
   - it has at least the minimum number of seeders and falls inside the size range

   Accepted releases are then ranked by group preference, then source preference (BluRay before WEB), then preferred codec, then seeders.
5. **Download.** The best release goes to qBittorrent through its WebUI API, with a category and tags so the app can track it.
6. **Import.** When the torrent completes, the app takes the main video (the largest file, skipping samples) plus any subtitles and puts them in `<library>/Title (Year)/Title (Year).mkv` (`.en.srt`, `.es.srt`, ...). It then sets permissions, removes the torrent (configurable), and asks Plex to rescan.
7. **Email.** It emails you the title, release, size and final path. You can also turn on emails when a download starts or when something fails.
8. **Self-healing.** A download that hasn't finished after `stalled_after` (default 3 days), or that errors in qBittorrent, is removed and blacklisted, and the title is searched again. Titles already in the library are skipped.

## Setup on Ubuntu

### 1. qBittorrent WebUI

Either install the desktop app and turn on *Tools → Options → Web UI*, or install the headless version:

```bash
sudo apt install qbittorrent-nox
sudo systemctl enable --now qbittorrent-nox@$USER   # WebUI on http://localhost:8080
```

Set a WebUI username and password. Running qBittorrent as the **same user** as movie-grabber avoids file-permission problems.

### 2. (Optional) Jackett or Prowlarr for more sites

Install [Prowlarr](https://wiki.servarr.com/prowlarr) or [Jackett](https://github.com/Jackett/Jackett), add the indexers you want, and copy each indexer's Torznab URL and the API key into `sources:` in the config.

### 3. Install movie-grabber

```bash
cd movie-grabber
sudo ./install.sh $USER
```

This creates a virtualenv in `/opt/movie-grabber`, the config in `/etc/movie-grabber/`, secrets in `/etc/movie-grabber.env`, a `movie-grabber` command and a systemd unit.

### 4. Configure

- `/etc/movie-grabber/config.yaml`: your Plex library folder(s), qBittorrent URL and user, quality rules, schedule and email. Every option is documented in [`config.example.yaml`](config.example.yaml).
- `/etc/movie-grabber.env`: `QB_PASSWORD=...`, `SMTP_PASSWORD=...`, and optionally `PLEX_TOKEN=...`.
  - **Gmail**: use an [App Password](https://myaccount.google.com/apppasswords), not your normal password (it needs 2-step verification turned on).
- `/etc/movie-grabber/movies.txt`: your wanted list.

### 5. Test, then start

```bash
movie-grabber test                          # checks qBittorrent, every source, library folders, sends a test email
movie-grabber search "The Matrix (1999)"    # dry run: shows what would be picked
movie-grabber search "Heat (1995)" --all    # also shows why other results were rejected

sudo systemctl enable --now movie-grabber@$USER
journalctl -u movie-grabber@$USER -f
```

## Commands

| Command | What it does |
|---|---|
| `movie-grabber run` | Daemon. Searches on the schedule and polls downloads. This is what systemd runs. |
| `movie-grabber once` | One download check and one search pass, then exits. Use it for cron. |
| `movie-grabber check` | Imports finished downloads only. Can be used as qBittorrent's "run on torrent finished" hook. |
| `movie-grabber search "Title (Year)" [--all]` | Dry-run search. Shows ranked candidates and reasons. |
| `movie-grabber status` | Every tracked title with its state (wanted / downloading / completed / gave_up). |
| `movie-grabber reset "Title (Year)" [--clear-blacklist]` | Marks a title as wanted again. |
| `movie-grabber test [--no-email]` | Checks connectivity and configuration. |

**Cron instead of the daemon**: for example, 4 times a day plus a download check every 10 minutes:

```cron
0 */6 * * *  /usr/local/bin/movie-grabber once
*/10 * * * * /usr/local/bin/movie-grabber check
```

## Notes

- **Multiple Plex libraries.** Define more roots under `library.roots` (for example `kids: /srv/media/Kids`) and end a line in `movies.txt` with `@kids`.
- **Keep seeding.** Set `library.transfer: hardlink` and `remove_torrent: false`. The file then appears in Plex instantly with no extra disk use while qBittorrent keeps seeding. This needs the download folder and the library on the same filesystem; otherwise the app falls back to copying.
- **qBittorrent in Docker.** Use `qbittorrent.path_map` to translate container paths (like `/downloads`) to host paths.
- **Plex scan.** Set `plex.url` and `PLEX_TOKEN` for an immediate rescan. Without them, Plex picks the file up on its next scheduled scan, or right away if "Scan my library automatically" is on.
- **Privacy.** Consider binding qBittorrent to a VPN interface (*Options → Advanced → Network interface*). Only download content you have the right to download in your country.
- **Site domains change.** YTS and TPB move domains from time to time; update `base_url`, or put them behind Jackett/Prowlarr, which tracks those changes for you.

## Development

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
