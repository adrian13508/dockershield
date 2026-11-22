#!/bin/sh
# Appends one row of repository numbers to a CSV file: stars, forks, release
# downloads, and the 14-day traffic totals and referrers GitHub keeps.
#
#   ./metrics.sh [file]          default file: metrics.csv
#
# Needs the gh CLI, authenticated as someone with push access to the
# repository: the traffic endpoints refuse everyone else. Reads only this
# repository's own numbers from the GitHub API. Nothing in the skobel
# binary reports anything; this script is the whole measurement.
#
# GitHub keeps traffic for 14 days only, so the row is a rolling window.
# Run it once a day (see .github/workflows/metrics.yml).
set -eu

REPO="${METRICS_REPO:-adrian13508/skobel}"
FILE="${1:-metrics.csv}"
HEADER="date,stars,forks,release_downloads,views_14d,unique_visitors_14d,clones_14d,unique_cloners_14d,referrers_14d"

today=$(date -u +%Y-%m-%d)
if [ -s "$FILE" ] && grep -q "^$today," "$FILE"; then
	echo "$FILE already has a row for $today" >&2
	exit 0
fi

# One call per endpoint; a failure of any of them stops the script before
# anything is written, so the file never gets a half-filled row.
repo=$(gh api "repos/$REPO" --jq '[.stargazers_count, .forks_count] | @csv')
# ponytail: first 100 releases only, paginate if the project ever has more
downloads=$(gh api "repos/$REPO/releases?per_page=100" --jq '[.[].assets[].download_count] | add // 0')
views=$(gh api "repos/$REPO/traffic/views" --jq '[.count, .uniques] | @csv')
clones=$(gh api "repos/$REPO/traffic/clones" --jq '[.count, .uniques] | @csv')
# referrer:views:unique visitors, separated by spaces, in one quoted CSV field
referrers=$(gh api "repos/$REPO/traffic/popular/referrers" \
	--jq '[.[] | "\(.referrer | gsub("[\",\\s]"; "_")):\(.count):\(.uniques)"] | join(" ")')

[ -s "$FILE" ] || echo "$HEADER" >"$FILE"
echo "$today,$repo,$downloads,$views,$clones,\"$referrers\"" >>"$FILE"
tail -n 1 "$FILE"
