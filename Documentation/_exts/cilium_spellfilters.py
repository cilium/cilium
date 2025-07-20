from enchant.tokenize import Filter

class WireGuardFilter(Filter):
    """Accept either 'wireguard' (for documenting Helm values) or 'WireGuard',
    but not 'Wireguard'.
    """

    def _skip(self, word):
        return (word == 'wireguard' or word == 'WireGuard')
