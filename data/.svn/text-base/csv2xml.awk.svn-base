BEGIN{ print "<?xml version=\"1.0\" encoding=\"utf-8\"?>"; print "<records>"; }
FNR<2{ for(i=1; i<=NF; i++) { label[i]=$i; } }
FNR>1{	print "<record>";
	for(i=1; i<=NF; i++) {
		print "<"label[i]">"$i"</"label[i]">";
	}
	print "</record>";
}
END{ print "</records>"; }
