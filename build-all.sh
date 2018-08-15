#GOOS=windows GOARCH=amd64 go install
go tool dist list

gocmd=cmd/sclient/main.go
golib=""
echo ""

echo ""
echo "Windows amd64"
GOOS=windows GOARCH=amd64 go build -o dist/windows/amd64/sclient.exe $gocmd $golib
echo "Windows 386"
GOOS=windows GOARCH=386 go build -o dist/windows/386/sclient.exe $gocmd $golib

echo ""
echo "Darwin (macOS) amd64"
GOOS=darwin GOARCH=amd64 go build -o dist/darwin/amd64/sclient $gocmd $golib

echo ""
echo "Linux amd64"
GOOS=linux GOARCH=amd64 go build -o dist/linux/amd64/sclient $gocmd $golib
echo "Linux 386"

echo ""
GOOS=linux GOARCH=386 go build -o dist/linux/386/sclient $gocmd $golib
echo "RPi 3 B+ ARMv7"
GOOS=linux GOARCH=arm GOARM=7 go build -o dist/linux/armv7/sclient $gocmd $golib
echo "RPi Zero ARMv5"
GOOS=linux GOARCH=arm GOARM=5 go build -o dist/linux/armv5/sclient $gocmd $golib

echo ""
echo ""

rsync -av ./dist/ root@telebit.cloud:/opt/telebit-relay/lib/extensions/admin/sclient/dist/
