cd kernel
VERSION=$(cat $PWD/../VERSION)
RELEASE=1
sudo make PACKAGE_NAME=rb_bpwatcher VERSION=$VERSION RELEASE=$RELEASE -f Makefile.dkms rpm
if [ $? -ne 0 ]; then
    echo "Failed to build RPM"
    exit 1
fi
sudo cp /var/lib/dkms/rb_bpwatcher/$VERSION/rpm/rb_bpwatcher-dkms-*.rpm $PWD/../
echo "RPM built successfully"
