#!/usr/bin/env bash
function badlinks_rec {
  for FILE in $1/*; do
    if [ -d "$FILE" ] && [ ! -h $FILE ]
      then badlinks_rec "$FILE" 
    fi

    if [ -h "$FILE" ] && [ ! -e "$FILE" ]; then
      T=$(expr $(date +%s) - $(stat -c %Y "$FILE"))
      if [ $T -gt 604800 ]; 
        then echo "$FILE";
      fi 
    fi
  done
}

badlinks_rec $1
