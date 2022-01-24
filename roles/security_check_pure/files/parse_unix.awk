BEGIN { printf "{"; }
/pam_unix\.so/{
  if($1 == "password" && $2 == "sufficient") {
    for(i = 4; i <= NF; i++) {
      if(substr($i, 1, 8) == "remember") {
          split($i, arr, "=")
          printf "\"%s\": \"%s\",", arr[1], arr[2]
      }
    }
  }
}
END { printf "\"__not_used__\": \"\"}"; }
