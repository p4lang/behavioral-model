class Libcrafter < Formula
  desc "C++ designed to create and decode network packets"
  homepage "https://github.com/pellegre/libcrafter"
  url "https://github.com/pellegre/libcrafter.git"
  version "0.1"

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool"  => :build
  depends_on "homebrew/dupes/libpcap"

  def install
    cd "libcrafter"
    system "./autogen.sh"
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    system "make", "check"
  end
end
