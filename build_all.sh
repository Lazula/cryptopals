for i in ./Set\ */*; do
  cd "$i"
  echo "Running $i/compile.sh"
  ./compile.sh
  cd "$OLDPWD"
done
