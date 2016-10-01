class Libjsonc < Formula
  desc "reference counting object model to construct JSON objects in C"
  homepage "https://github.com/json-c/json-c"
  url "https://github.com/json-c/json-c.git", :branch => "json-c-0.12"
  version "0.12"

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool"  => :build

  def install
    system "sh", "autogen.sh"
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    system "make", "check"
  end
end
