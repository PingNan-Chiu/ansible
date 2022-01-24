BEGIN { printf "{"; }
/pam_pwquality\.so/{
  for(i = 1; i <= NF; i++) {
    if(substr($i, 1, 5) == "retry" || substr($i, 1, 6) == "minlen" || substr($i, 1, 7) == "dcredit"  || substr($i, 1, 7) == "lcredit") {
        split($i, arr, "=")
        printf "\"%s\": \"%s\",", arr[1], arr[2]
    }
  }
}
END { printf "\"__not_used__\": \"\"}"; }
