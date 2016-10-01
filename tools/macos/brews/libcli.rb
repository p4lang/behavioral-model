class Libcli < Formula
  desc "libcli emulates a cisco style telnet command-line interface"
  homepage "https://github.com/dparrish/libcli"
  url "https://github.com/dparrish/libcli.git", :using => :git, :branch => "stable"
  version "1.9.7"

  def install
    system "make"
    system "make", "install", "PREFIX=#{prefix}"
  end

  test do
    system "true"
  end
end
