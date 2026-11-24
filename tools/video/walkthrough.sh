#!/bin/sh
# Mintprobe walkthrough video: intro card + A (public mint, free checks) + B (test mint, with ecash) + C (matrix) + outro -> public/walkthrough.mp4
# Inputs: the webm recordings from tools/demo-video.mjs (run against the live site).
set -e
cd "$(dirname "$0")"
R=$(cd ../.. && pwd)
A=$(ls -t $R/shots/video/a/*.webm | head -1)
B=$(ls -t $R/shots/video/b/*.webm | head -1)
C=$(ls -t $R/shots/video/c/*.webm | head -1)
F=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
FB=/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf
W=1100; H=760; CH=96; BG=0x0d1117
rm -rf t; mkdir -p t
cap() { printf '%s' "$2" > t/$1.txt; }
cap a1 "Mintprobe: paste any Cashu mint URL. This is mint.minibits.cash, a real public mint. The checks run in your browser and need no ecash."
cap a2 "Each check is written from the text of the NUT specs and says why it passes, fails or warns."
cap a3 "Open a row to see the exact request and reply. Here NUT-17: the mint must first send the current state, and this one does not (reported as cdk#2981, fix in cdk#2982)."
cap b1 "Now testnut, a test mint whose Lightning is fake: the free checks first."
cap b2 "Then \"Run with ecash\": the page mints 100 sat and spends it."
cap b3 "DLEQ (NUT-12), exact fees, double spend, SPENT state, P2PK 2-of-2 and SIG_ALL (NUT-11), HTLC (NUT-14), cached replies (NUT-19), signed quotes (NUT-20), restore (NUT-09)..."
cap b4 "A real failure: an HTLC refund signed with the refund key alone is refused, because the mint reads a witness without a preimage as P2PK."
cap c1 "Public mints today: the same checks, run from a server on 15 mints. Click a mint to run it live."
dt() { echo "drawtext=fontfile=$F:textfile=t/$1.txt:fontcolor=white:fontsize=21:line_spacing=6:x=28:y=$H+14:enable='between(t,$2,$3)'"; }
wrap() { fold -s -w 92 t/$1.txt > t/$1.w && mv t/$1.w t/$1.txt; }
for c in a1 a2 a3 b1 b2 b3 b4 c1; do wrap $c; done
base="scale=$W:$H,pad=$W:$H+$CH:0:0:color=$BG,fps=25,format=yuv420p"
ffmpeg -v error -y -i "$A" -vf "$base,$(dt a1 0 9.5),$(dt a2 9.5 15.2),$(dt a3 15.2 22)" -an -c:v libx264 -crf 26 -preset slow t/A.mp4
ffmpeg -v error -y -i "$B" -vf "$base,$(dt b1 0 10.5),$(dt b2 10.5 15),$(dt b3 15 34),$(dt b4 34 43)" -an -c:v libx264 -crf 26 -preset slow t/B.mp4
ffmpeg -v error -y -i "$C" -vf "$base,$(dt c1 0 7)" -an -c:v libx264 -crf 26 -preset slow t/C.mp4
card() { # name seconds title line1 line2
  printf '%s' "$3" > t/$1_t.txt; printf '%s' "$4" > t/$1_1.txt; printf '%s' "$5" > t/$1_2.txt
  ffmpeg -v error -y -f lavfi -i "color=c=$BG:s=${W}x$((H+CH)):d=$2:r=25" -vf "drawtext=fontfile=$FB:textfile=t/$1_t.txt:fontcolor=white:fontsize=64:x=(w-tw)/2:y=h/2-110,drawtext=fontfile=$F:textfile=t/$1_1.txt:fontcolor=0xf0b429:fontsize=28:x=(w-tw)/2:y=h/2+0,drawtext=fontfile=$F:textfile=t/$1_2.txt:fontcolor=0xa8b3c1:fontsize=24:x=(w-tw)/2:y=h/2+60,format=yuv420p" -c:v libx264 -crf 26 t/$1.mp4
}
card intro 3.5 "Mintprobe" "Does your Cashu mint speak the NUTs?" "Any mint URL  ·  every request and reply on screen  ·  #NutNovember"
card mid 2.5 "With ecash" "On a test mint the page mints, swaps and melts for real" "P2PK, HTLC, DLEQ, fees, double spends"
card outro 5 "Try it" "mmajjd926-netizen.github.io/mintprobe" "Open source (MIT)  ·  findings: cdk#2980, cdk#2981, fix in cdk#2982"
printf "file 'intro.mp4'\nfile 'A.mp4'\nfile 'mid.mp4'\nfile 'B.mp4'\nfile 'C.mp4'\nfile 'outro.mp4'\n" > t/list.txt
ffmpeg -v error -y -f concat -safe 0 -i t/list.txt -c:v libx264 -crf 27 -preset slow -movflags +faststart -pix_fmt yuv420p $R/public/walkthrough.mp4
ffmpeg -v error -y -ss 20 -i $R/public/walkthrough.mp4 -frames:v 1 -q:v 4 $R/docs/walkthrough.jpg
rm -rf t
ls -la $R/public/walkthrough.mp4 $R/docs/walkthrough.jpg
