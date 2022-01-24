BEGIN { printf "{"; }
/pam_tally2\.so/{
  for(i = 1; i <= NF; i++) {
    if(substr($i, 1, 11) == "unlock_time") {
        split($i, arr, "=")
        printf "\"%s\": \"%s\",", arr[1], arr[2]
    }
  }
}
END { printf "\"__not_used__\": \"\"}"; }
