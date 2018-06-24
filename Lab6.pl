use strict;
use warnings;

use experimental 'smartmatch'; # фикс для сравнения строк при использовании strict

use utf8;

use Data::Dumper; # модуль для дебага

if (not scalar(@ARGV)) {
    print "no input directory\n";
    exit 1;
}

my $DEBUG = 0;

my $logdir = $ARGV[0];

die "\"$logdir\" is not a directory" if !-d $logdir;

my $logfile = $logdir . '/access.log';

my $limit = $ARGV[1] // 50;

my $re_bad_useragent = qr/crawler|webdav|evil|http|node|ahref|guzzleh|p(?:erl|ython|hp)|survey|nmap|curl|indy[\s\t]+library|urllib|spider|anyevent|masscan|cloud|zeus|zmeu|mor(?:f|ph)eus|fuck|scan|\=|mozilla\/4\.|jorgee|^[^\s]+$/i;
my $re_good_requests = qr/.*/;
my $re_bad_request = qr/^\$|[:<>-]|\/\/|\.\.|\.(?:php|cgi|bs|pl)|sql|\.[^\/\s]+\/|\\x.+|backup|\/wp-[^-]|phpmyad|admin|cpanel|vhosts|p\/m\/a|bbs|xampp|/i;
my $re_bad_request_cs = qr/\/(?:README|FAQ)/;
my $re_good_referer = qr/https?\/\/:(?:mysite.fr|(?:www\.)?(?:google\.(?:com|ru|fr|hk|jp|co\.uk|br|cc))|yandex\.ru|bing\.com)\//i;

my @bad_status_codes = qw(499 403);
my @allowed_request_methods = qw(get head post);

my @whitelisted_ips = qw(127.0.0.1);

my @items;

my %items_filter;

sub read_file {
    my ($file, $type) = @_;

    my ($exec, $fh);

    if ($type eq '') {
        $exec = $file;
        $type = '<'; # режим чтения файла
    } elsif ($type eq 'bz2') {
        $exec = "bzip2 -d \"${file}\" --stdout"; # запускаем bzip2 для арспаковки архива и передачи распакованного текста через stdout дальше по пайпу
        $type = '-|'; # режим чтения из пайпа
    } elsif ($type eq 'gz') {
        $exec = "gzip -d \"${file}\" --stdout";
        $type = '-|';
    }

    open($fh, $type, $exec) or die "access denied: \"${file}\"";

    while(my $line = readline($fh)) {
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+([^\s])+\s+([^\s]+)\s+\[([^\s\]]+)\s+([^\s\]]+)\]\s+"(?:(get|head|post)\s+)?([^"]+)"\s+(\d+)\s+\d+\s+"([^"]+)"\s+"([^"]+)"/) {
            push @items, {
                    "ip" => $1,
                    "blank" => $2,
                    "user" => $3,
                    "datetime" => $4,
                    "timezone" => $5,
                    "method" => $6,
                    "request" => $7,
                    "status" => $8,
                    "referer" => $9,
                    "user-agent" => $10
                };
        }
    }

    close($fh);
}

sub read_dir {
    my $dir = shift;
    my $ext = shift;

    opendir(my $dh, $logdir);

    read_file("${dir}/$_", $ext) for grep { -f "${dir}/$_" && /access\.log\.${ext}(?:\.|\$)?/ } readdir($dh); # фильтрация по значению, а также проверка существования файла с указанным путём

    closedir $dh;
}

sub get_key {
    my $item = shift;

    return $$item{'request'};
}

sub classifier {
    my $item = shift;

    # ~~ оператор проверки вхождения элемента в список
    if ($$item{'ip'} ~~ @whitelisted_ips) { # если элемент находится в белом списке, то ничего даже не проверяем, риск равен нулю
        print "whitelisted ip: $$item{'ip'}" if $DEBUG;

        return 0;
    }

    my $risk = 0; # общий уровень угрозы
    my @list;

    $risk++ and join @list, "status: $$item{'status'}" if $$item{'status'} ~~ @bad_status_codes;
    $risk++ and join @list, "method: $$item{'method'}" if $$item{'method'} and not ((lc $$item{'method'}) ~~ @allowed_request_methods); # lc - оператор перевода текста в нижний регистр
    $risk++ and join @list, "user-agent: $$item{'user-agent'}" if $$item{'user-agent'} =~ $re_bad_useragent;
    $risk++ and join @list, "request_i: $$item{'request'}" if $$item{'request'} =~ $re_bad_request;
    $risk++ and join @list, "request_cs: $$item{'request'}" if $$item{'request'} =~ $re_bad_request_cs;
    $risk++ and join @list, "request_good: $$item{'request'}" if not ($$item{'request'} =~ $re_good_requests);
    $risk++ and join @list, "referer: $$item{'referer'}" if not ($$item{'referer'} =~ $re_good_referer);

    if ($DEBUG) {
        print Dumper $item;
        print "\n\n";

        print join @list, "\n";
        print("\n\n");
    }

    return $risk;
}

read_file($logfile, '') if -f $logfile;

read_dir($logdir, 'bz2');
read_dir($logdir, 'gz');

for my $item (@items) {
    my $key = get_key($item);
    my $risk = classifier($item);

    $items_filter{$key} = $items_filter{$key} ? ++$items_filter{$key} : 1 if $risk >= 2; # как в предыдущей лабе, только с добавлением условия, что risk должен быть >= 2
}

print "$items_filter{$_}: ${_}\n" for grep { $_ && $items_filter{$_} } ((reverse sort { $items_filter{$a} <=> $items_filter{$b} || $b cmp $a } keys %items_filter)[0..$limit - 1]); # сначала значения списка ключей сортируются по их значениям в хеш-таблице через оператор <=>, а затем ключи с одинаковыми значениями сортируются, как строки, по алфавиту через оператор cmp
