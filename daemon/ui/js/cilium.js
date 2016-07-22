function getFmtLabel(rawLabel) {
	var lbl = rawLabel.source + ":" + rawLabel.key;
	if (rawLabel.value != null) {
		lbl += "=" + rawLabel.value;
	}
	return lbl;
}

function createCiliumLabel(rawString) {
	var lbl = {Key: "", Source: ""};

	ret = parseSource(rawString);
	var src = ret[0];
	var next = ret[1];
	if (src != "") {
		lbl.Source = src;
	} else {
		lbl.Source = "io.cilium";
	}

	var keySplit = next.split("=");
	lbl.Key = keySplit[0];
	if (keySplit.length > 1) {
		if (src == "reserved" && keySplit[0] == "") {
			lbl.Key = keySplit[1];
		} else {
			lbl.Value = keySplit[1];
		}
	}
	return lbl;
}

function parseSource(rawString) {
	if (rawString == "") {
		return ["", ""];
	}
	if (rawString.charAt(0) == '$') {
		rawString = rawString.replace(/^\$/, "reserved:");
	}
	var sourceSplit = rawString.split(":");
	if (sourceSplit.length < 2) {
		next = sourceSplit[0];
		if (next.startsWith("io.cilium.reserved")) {
			src = "reserved";
			next = next.replace(/^io\.cilium\.reserved/);
		}
	} else {
		if (sourceSplit[0] != "") {
			src = sourceSplit[0];
		}
		next = sourceSplit.slice(1, sourceSplit.length).join(":");
	}
	return [src, next];
}