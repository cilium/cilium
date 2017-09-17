#! /bin/sh

FILE=$(echo $1 | sed s/.go/_gen.go/)
echo "searching" $FILE "for" $2
grep -q $2 $FILE
if [ $? -eq 0  ]
then
    echo "OK"
else
    echo "whoops!"
    exit 1
fi
