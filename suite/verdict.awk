# Judges SQLite's testrunner.log, read twice. The first pass finds the unfreed memory most files report, which is
# SQLite3MC's global cipher tables, and the second holds every file to it, to its summary line, and to the
# expected failures and crashes named in the variables failures and crashes.

BEGIN {
    n = split(failures, list)
    for (i = 1; i <= n; i++) expected[list[i]] = 1
    n = split(crashes, list)
    for (i = 1; i <= n; i++) crash[list[i]] = 1
}

FNR == 1 { pass++ }

pass == 1 {
    if (/^Unfreed memory: /) leaks[$0]++
    next
}

FNR == 1 {
    for (line in leaks) if (leaks[line] > leaks[baseline]) baseline = line
    print "baseline  " (baseline == "" ? "All memory allocations freed" : baseline)
}

# A file that returns early, as the Windows-only ones do here, ends done without a summary. A crash ends failed.
/^### / { finish(); file = $2; state = $NF; next }
/^[0-9]+ errors out of [0-9]+ tests/ { errors = $1; total = $5; summary = 1 }
/^!Failures on these tests:/ { listed = substr($0, length("!Failures on these tests:") + 1) }
/^==[0-9]+==(ERROR|WARNING): |runtime error: / { if (sanitizer == "") sanitizer = $0 }
/^Unfreed memory: / { leak = $0 }
/ files were left open$/ { open_files = $0 }
/^!|^==[0-9]+==|^SUMMARY: |runtime error: / { if (lines++ < 20) details = details "    " $0 "\n" }

function finish(    name, problem, n, i, names) {
    if (file == "") return
    name = file
    sub(/.*\//, "", name)
    sub(/\.test$/, "", name)
    files++
    if (name in crash) {
        crashed[name] = 1
        if (summary || state != "(failed)") {
            print "FAIL  " name "  no longer crashes, so drop it from EXPECTED_CRASHES"
            bad = 1
        } else {
            print "crash " name "  as expected"
        }
    } else if (!summary && state == "(done)" && sanitizer == "") {
        returned = returned " " name
    } else {
        problem = ""
        if (!summary) problem = ", no summary line"
        n = split(listed, names)
        if (summary && errors != n) problem = problem ", " errors " errors but " n " named failures"
        for (i = 1; i <= n; i++) {
            if (names[i] in expected) failed[names[i]] = 1
            else problem = problem ", unexpected failure " names[i]
        }
        if (sanitizer != "") problem = problem ", " sanitizer
        if (leak != "" && leak != baseline) problem = problem ", " leak
        if (open_files != "") problem = problem ", " open_files
        if (problem != "") {
            print "FAIL  " name "  " substr(problem, 3)
            printf "%s", details
            bad = 1
        } else {
            tests += total
        }
    }
    file = state = listed = sanitizer = leak = open_files = details = ""
    summary = lines = 0
}

END {
    finish()
    for (name in expected) {
        if (name in failed) print "known " name
        else { print "FAIL  " name "  passes now, so drop it from EXPECTED_FAILURES"; bad = 1 }
    }
    for (name in crash) if (!(name in crashed)) { print "FAIL  " name "  did not run"; bad = 1 }
    if (files == 0) { print "FAIL  testrunner ran no files"; bad = 1 }
    if (returned != "") print "returned before their summary:" returned
    print files " files, " tests " tests in the files that passed"
    exit bad
}
