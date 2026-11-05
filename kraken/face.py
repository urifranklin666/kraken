"""The KRAKEN face: a small, deterministic mood engine.

Faces are original; they only nod to the tamagotchi idea.  The engine is pure
so it can be unit-tested and rendered by the daemon, CLI, polybar and web UI.
"""

from __future__ import annotations

from dataclasses import dataclass

# Faces stay inside the JetBrainsMono Nerd Font glyph set: the bar drops
# characters it cannot draw (fullwidth hyphens, katakana) and the face turns
# into a gap.
FACES = {
    "sleeping": "(-_-) zZ",
    "bored": "(¬_¬ )",
    "chill": "(◕‿◕)",
    "focused": "(■_■)",
    "excited": "(^▽^)",
    "proud": "(■‿■)",
    "alert": "(°_°)",
}

MOOD_COLORS = {
    "sleeping": "muted",
    "bored": "yellow",
    "chill": "green",
    "focused": "cyan",
    "excited": "magenta",
    "proud": "green",
    "alert": "red",
}

BLURBS = {
    "sleeping": "Radios parked. The lab is quiet.",
    "bored": "Listening… the airwaves are too clean.",
    "chill": "Hopping channels, collecting whispers.",
    "focused": "Locked on. Watching every beacon.",
    "excited": "Fresh networks! The spectrum is alive.",
    "proud": "Handshake secured. Nice.",
    "alert": "Something changed. Check the radios.",
}


@dataclass(frozen=True)
class Face:
    mood: str
    face: str
    color: str
    blurb: str
    epoch: int

    def as_dict(self) -> dict[str, object]:
        return {
            "mood": self.mood,
            "face": self.face,
            "color": self.color,
            "blurb": self.blurb,
            "epoch": self.epoch,
        }


def compute_face(
    *,
    mode: str,
    uptime: float,
    handshakes_recent: int = 0,
    new_aps_recent: int = 0,
    seconds_since_activity: float = 0.0,
    hops: int = 0,
) -> Face:
    """Derive a face from recent activity.

    ``handshakes_recent`` and ``new_aps_recent`` count events in the last two
    minutes.  ``seconds_since_activity`` is time since the last new AP,
    handshake or frame.
    """
    epoch = int(max(0.0, uptime) // 300)

    if mode == "idle":
        mood = "sleeping"
    elif handshakes_recent > 0:
        mood = "proud"
    elif new_aps_recent >= 3:
        mood = "excited"
    elif mode in ("recon", "hybrid") and seconds_since_activity < 90:
        mood = "focused"
    elif mode in ("recon", "hybrid") and seconds_since_activity > 900:
        mood = "bored"
    elif mode in (
        "recon",
        "hybrid",
    ):
        mood = "chill" if hops else "alert"
    else:
        mood = "chill"

    return Face(
        mood=mood,
        face=FACES[mood],
        color=MOOD_COLORS[mood],
        blurb=BLURBS[mood],
        epoch=epoch,
    )
