from sphinx.writers.html5 import HTML5Translator

# Make all external links open in new tabs
class PatchedHTMLTranslator(HTML5Translator):
    def starttag(self, node, tagname, *args, **attrs):
        if (
            tagname == "a"
            and "target" not in attrs
            and (
                "external" in attrs.get("class", "")
                or "external" in attrs.get("classes", [])
            )
        ):
            attrs["target"] = "_blank"
            attrs["ref"] = "noopener noreferrer"
        return super().starttag(node, tagname, *args, **attrs)
