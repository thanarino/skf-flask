"use strict";

function updateScores() {
    var result = CVSS_export.calculateCVSSFromMetrics(inputValue('input[type="radio"][name=AV]:checked'), inputValue('input[type="radio"][name=AC]:checked'), inputValue('input[type="radio"][name=PR]:checked'), inputValue('input[type="radio"][name=UI]:checked'), inputValue('input[type="radio"][name=S]:checked'), inputValue('input[type="radio"][name=C]:checked'), inputValue('input[type="radio"][name=I]:checked'), inputValue('input[type="radio"][name=A]:checked'), inputValue('input[type="radio"][name=E]:checked'), inputValue('input[type="radio"][name=RL]:checked'), inputValue('input[type="radio"][name=RC]:checked'), inputValue('input[type="radio"][name=CR]:checked'), inputValue('input[type="radio"][name=IR]:checked'), inputValue('input[type="radio"][name=AR]:checked'), inputValue('input[type="radio"][name=MAV]:checked'), inputValue('input[type="radio"][name=MAC]:checked'), inputValue('input[type="radio"][name=MPR]:checked'), inputValue('input[type="radio"][name=MUI]:checked'), inputValue('input[type="radio"][name=MS]:checked'), inputValue('input[type="radio"][name=MC]:checked'), inputValue('input[type="radio"][name=MI]:checked'), inputValue('input[type="radio"][name=MA]:checked'));
    if (result.success === true) {
        var L = document.querySelectorAll(".needBaseMetrics"),
            i = L.length;
        while (i--) {
            hide(L[i])
        }
        parentNode(text("#baseMetricScore", result.baseMetricScore), ".scoreRating").className = "scoreRating " + result.baseSeverity.toLowerCase();
        text("#baseSeverity", "(" + result.baseSeverity + ")");
        // parentNode(text("#temporalMetricScore", result.temporalMetricScore), ".scoreRating").className = "scoreRating " + result.temporalSeverity.toLowerCase();
        // text("#temporalSeverity", "(" + result.temporalSeverity + ")");
        // parentNode(text("#environmentalMetricScore", result.environmentalMetricScore), ".scoreRating").className = "scoreRating " + result.environmentalSeverity.toLowerCase();
        // text("#environmentalSeverity", "(" + result.environmentalSeverity + ")");
        show(inputValue("#vectorString", result.vectorString));
        window.location.hash = result.vectorString
    } else {
        if (result.error === "Not all base metrics were given - cannot calculate scores.") {
            var L = document.querySelectorAll(".needBaseMetrics"),
                i = L.length;
            while (i--) {
                show(L[i])
            }
            hide("#vectorString")
        }
    }
}

function delayedUpdateScores() {
    setTimeout(updateScores, 100)
}
window.Element && function (ElementPrototype) {
    ElementPrototype.matchesSelector = ElementPrototype.matchesSelector || ElementPrototype.mozMatchesSelector || ElementPrototype.msMatchesSelector || ElementPrototype.oMatchesSelector || ElementPrototype.webkitMatchesSelector || function (selector) {
        var node = this,
            nodes = (node.parentNode || node.document).querySelectorAll(selector),
            i = -1;
        while (nodes[++i] && nodes[i] != node) {}
        return !!nodes[i]
    }
}(Element.prototype);
var matchesSelector = function (node, selector) {
    if (!("parentNode" in node) || !node.parentNode) {
        return false
    }
    return Array.prototype.indexOf.call(node.parentNode.querySelectorAll(selector)) != -1
};

function node() {
    for (var i = 0; i < arguments.length; i++) {
        var o = arguments[i];
        if (typeof (o) == "string" && o) {
            return document.querySelector(o)
        } else {
            if ("nodeName" in o) {
                return o
            } else {
                if ("jquery" in o) {
                    return o.get(0)
                }
            }
        }
    }
    return false
}

function parentNode(p, q) {
    if (!p || !(p = node(p))) {
        return
    } else {
        if ((typeof (q) == "string" && p.matchesSelector(q)) || p == q) {
            return p
        } else {
            if (p.nodeName.toLowerCase() != "html") {
                return parentNode(p.parentNode, q)
            } else {
                return
            }
        }
    }
}

function bind(q, tg, fn) {
    var o = node(q);
    if (!o) {
        return
    }
    if (o.addEventListener) {
        o.addEventListener(tg, fn, false)
    } else {
        if (o.attachEvent) {
            o.attachEvent("on" + tg, fn)
        } else {
            o["on" + tg] = fn
        }
    }
    return o
}

function text(q, s) {
    var e = node(q);
    if (!e) {
        return
    }
    if (arguments.length > 1) {
        if ("textContent" in e) {
            e.textContent = s
        } else {
            e.innerText = s
        }
        return e
    }
    return e.textContent || e.innerText
}

function hide(q) {
    var e = node(q);
    if (!e) {
        return
    }
    e.setAttribute("style", "display:none");
    return e
}

function show(q) {
    var e = node(q);
    if (!e) {
        return
    }
    // e.setAttribute("style", "display:inline-block");
    return e
}

function inputValue(q, v) {
    var e = document.querySelector(q);
    if (!e || e.nodeName.toLowerCase() != "input") {
        return
    }
    if (arguments.length > 1) {
        e.value = v;
        return e
    }
    return e.value
}

function setMetricsFromVector(vectorString) {
    var result = true;
    var urlMetric;
    var metricValuesToSet = {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
        E: "X",
        RL: "X",
        RC: "X",
        CR: "X",
        IR: "X",
        AR: "X",
        MAV: "X",
        MAC: "X",
        MPR: "X",
        MUI: "X",
        MS: "X",
        MC: "X",
        MI: "X",
        MA: "X"
    };
    var vectorStringRegex_30 = /^CVSS:3.0\/((AV:[NALP]|AC:[LH]|PR:[UNMLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLMH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/;
    if (vectorStringRegex_30.test(vectorString)) {
        var urlMetrics = vectorString.substring("CVSS:3.0/".length).split("/");
        for (var p in urlMetrics) {
            var urlMetric = urlMetrics[p].split(":");
            metricValuesToSet[urlMetric[0]] = urlMetric[1]
        }
        if (metricValuesToSet.AV !== undefined && metricValuesToSet.AC !== undefined && metricValuesToSet.PR !== undefined &&  metricValuesToSet.C !== undefined && metricValuesToSet.I !== undefined && metricValuesToSet.A !== undefined) {
            for (var p in metricValuesToSet) {
                var q = document.getElementById(p + "_" + metricValuesToSet[p]);
                if (q) {
                    q.checked = true
                }
            }
        } else {
            result = "NotAllBaseMetricsProvided"
        }
    } else {
        result = "MalformedVectorString"
    }
    updateScores();
    return result
}
var CVSSVectorInURL;

function urlhash() {
    var h = window.location.hash;
    CVSSVectorInURL = h;
    setMetricsFromVector(h.substring(1))
}

function inputSelect() {
    this.setSelectionRange(0, this.value.length)
}

function cvssCalculator() {
    if (!("CVSS_export" in window) || !("CVSS_Help" in window)) {
        setTimeout(cvssCalculator, 100);
        return
    }
    var L, i, n;
    L = document.querySelectorAll(".cvss-calculator input");
    i = L.length;
    while (i--) {
        bind(L[i], "click", delayedUpdateScores)
    }
    for (n in CVSS_Help.helpText_en) {
        document.getElementById(n).setAttribute("title", CVSS_Help.helpText_en[n])
    }
    urlhash();
    if (("onhashchange" in window)) {
        window.onhashchange = urlhash
    }
    bind(bind("#vectorString", "click", inputSelect), "contextmenu", inputSelect)
}
cvssCalculator();

