from __future__ import annotations

import re


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_@./:-]+|[^\s]")


def simple_word_tokenize(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text)


def word_shape(token: str) -> str:
    shape = []
    for char in token[:24]:
        if char.isupper():
            shape.append("X")
        elif char.islower():
            shape.append("x")
        elif char.isdigit():
            shape.append("0")
        else:
            shape.append(char)
    return "".join(shape)


def token_to_features(tokens: list[str], index: int) -> dict[str, object]:
    token = tokens[index]
    lower = token.lower()

    features: dict[str, object] = {
        "bias": 1.0,
        "token.lower": lower,
        "token[-3:]": lower[-3:],
        "token[-2:]": lower[-2:],
        "token[:3]": lower[:3],
        "token.isupper": token.isupper(),
        "token.istitle": token.istitle(),
        "token.isdigit": token.isdigit(),
        "token.has_digit": any(char.isdigit() for char in token),
        "token.has_hyphen": "-" in token,
        "token.has_dot": "." in token,
        "token.has_at": "@" in token,
        "token.shape": word_shape(token),
    }

    if index == 0:
        features["BOS"] = True
    else:
        prev = tokens[index - 1]
        prev_lower = prev.lower()
        features.update(
            {
                "-1:token.lower": prev_lower,
                "-1:token.istitle": prev.istitle(),
                "-1:token.isupper": prev.isupper(),
                "-1:token.shape": word_shape(prev),
            }
        )

    if index == len(tokens) - 1:
        features["EOS"] = True
    else:
        nxt = tokens[index + 1]
        next_lower = nxt.lower()
        features.update(
            {
                "+1:token.lower": next_lower,
                "+1:token.istitle": nxt.istitle(),
                "+1:token.isupper": nxt.isupper(),
                "+1:token.shape": word_shape(nxt),
            }
        )

    return features


def sentence_to_feature_dicts(tokens: list[str]) -> list[dict[str, object]]:
    return [token_to_features(tokens, index) for index in range(len(tokens))]

