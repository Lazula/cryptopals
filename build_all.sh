for i in ./Set\ */*; do
  cd "$i"
  echo "Running $i Makefile"
  make
  cd "$OLDPWD"
done
