import re

def capitalize_first(text):
    """
    Trims whitespace, removes invalid characters, and capitalizes the first letter of the given text.
    Only allows letters, numbers, spaces, and basic punctuation (.,!?-').
    Returns an empty string if input is invalid or empty.
    """
    if not text:
        return ""
    text = text.strip()
    # Remove unwanted characters (allow letters, numbers, spaces, . , ! ? - ')
    text = re.sub(r"[^a-zA-Z0-9 .,!?\-']", "", text)
    if not text:
        return ""
    return text[0].upper() + text[1:] if len(text) > 1 else text.upper()

def capitalize_name(name):
    """
    Trims whitespace, removes invalid characters, and capitalizes each part of a name.
    Handles hyphenated names and multiple spaces. Only allows letters, spaces, and hyphens.
    Returns an empty string if input is invalid or empty.
    """
    if not name:
        return ""
    name = name.strip()
    # Remove unwanted characters (allow letters, spaces, hyphens)
    name = re.sub(r"[^a-zA-Z \-]", "", name)
    if not name:
        return ""
    return ' '.join(
        '-'.join(part.capitalize() for part in word.split('-'))
        for word in name.split()
    ) 