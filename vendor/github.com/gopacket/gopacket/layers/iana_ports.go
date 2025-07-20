// Copyright 2012 Google, Inc. All rights reserved.

package layers

// Created by gen.go, don't edit manually
// Generated at 2023-07-28 17:00:37.114586196 +0400 +04 m=+2.218439472
// Fetched from "http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml"

// TCPPortNames contains the port names for all TCP ports.
func TCPPortNames(port TCPPort) (string, bool) {
	switch port {
	case 1:
		return "tcpmux", true
	case 2:
		return "compressnet", true
	case 3:
		return "compressnet", true
	case 5:
		return "rje", true
	case 7:
		return "echo", true
	case 9:
		return "discard", true
	case 11:
		return "systat", true
	case 13:
		return "daytime", true
	case 17:
		return "qotd", true
	case 18:
		return "msp", true
	case 19:
		return "chargen", true
	case 20:
		return "ftp-data", true
	case 21:
		return "ftp", true
	case 22:
		return "ssh", true
	case 23:
		return "telnet", true
	case 25:
		return "smtp", true
	case 27:
		return "nsw-fe", true
	case 29:
		return "msg-icp", true
	case 31:
		return "msg-auth", true
	case 33:
		return "dsp", true
	case 37:
		return "time", true
	case 38:
		return "rap", true
	case 39:
		return "rlp", true
	case 41:
		return "graphics", true
	case 42:
		return "name", true
	case 43:
		return "nicname", true
	case 44:
		return "mpm-flags", true
	case 45:
		return "mpm", true
	case 46:
		return "mpm-snd", true
	case 48:
		return "auditd", true
	case 49:
		return "tacacs", true
	case 50:
		return "re-mail-ck", true
	case 52:
		return "xns-time", true
	case 53:
		return "domain", true
	case 54:
		return "xns-ch", true
	case 55:
		return "isi-gl", true
	case 56:
		return "xns-auth", true
	case 58:
		return "xns-mail", true
	case 62:
		return "acas", true
	case 63:
		return "whoispp", true
	case 64:
		return "covia", true
	case 65:
		return "tacacs-ds", true
	case 66:
		return "sql-net", true
	case 67:
		return "bootps", true
	case 68:
		return "bootpc", true
	case 69:
		return "tftp", true
	case 70:
		return "gopher", true
	case 71:
		return "netrjs-1", true
	case 72:
		return "netrjs-2", true
	case 73:
		return "netrjs-3", true
	case 74:
		return "netrjs-4", true
	case 76:
		return "deos", true
	case 78:
		return "vettcp", true
	case 79:
		return "finger", true
	case 80:
		return "http", true
	case 82:
		return "xfer", true
	case 83:
		return "mit-ml-dev", true
	case 84:
		return "ctf", true
	case 85:
		return "mit-ml-dev", true
	case 86:
		return "mfcobol", true
	case 88:
		return "kerberos", true
	case 89:
		return "su-mit-tg", true
	case 90:
		return "dnsix", true
	case 91:
		return "mit-dov", true
	case 92:
		return "npp", true
	case 93:
		return "dcp", true
	case 94:
		return "objcall", true
	case 95:
		return "supdup", true
	case 96:
		return "dixie", true
	case 97:
		return "swift-rvf", true
	case 98:
		return "tacnews", true
	case 99:
		return "metagram", true
	case 101:
		return "hostname", true
	case 102:
		return "iso-tsap", true
	case 103:
		return "gppitnp", true
	case 104:
		return "acr-nema", true
	case 105:
		return "cso", true
	case 106:
		return "3com-tsmux", true
	case 107:
		return "rtelnet", true
	case 108:
		return "snagas", true
	case 109:
		return "pop2", true
	case 110:
		return "pop3", true
	case 111:
		return "sunrpc", true
	case 112:
		return "mcidas", true
	case 113:
		return "ident", true
	case 115:
		return "sftp", true
	case 116:
		return "ansanotify", true
	case 117:
		return "uucp-path", true
	case 118:
		return "sqlserv", true
	case 119:
		return "nntp", true
	case 120:
		return "cfdptkt", true
	case 121:
		return "erpc", true
	case 122:
		return "smakynet", true
	case 123:
		return "ntp", true
	case 124:
		return "ansatrader", true
	case 125:
		return "locus-map", true
	case 126:
		return "nxedit", true
	case 127:
		return "locus-con", true
	case 128:
		return "gss-xlicen", true
	case 129:
		return "pwdgen", true
	case 130:
		return "cisco-fna", true
	case 131:
		return "cisco-tna", true
	case 132:
		return "cisco-sys", true
	case 133:
		return "statsrv", true
	case 134:
		return "ingres-net", true
	case 135:
		return "epmap", true
	case 136:
		return "profile", true
	case 137:
		return "netbios-ns", true
	case 138:
		return "netbios-dgm", true
	case 139:
		return "netbios-ssn", true
	case 140:
		return "emfis-data", true
	case 141:
		return "emfis-cntl", true
	case 142:
		return "bl-idm", true
	case 143:
		return "imap", true
	case 144:
		return "uma", true
	case 145:
		return "uaac", true
	case 146:
		return "iso-tp0", true
	case 147:
		return "iso-ip", true
	case 148:
		return "jargon", true
	case 149:
		return "aed-512", true
	case 150:
		return "sql-net", true
	case 151:
		return "hems", true
	case 152:
		return "bftp", true
	case 153:
		return "sgmp", true
	case 154:
		return "netsc-prod", true
	case 155:
		return "netsc-dev", true
	case 156:
		return "sqlsrv", true
	case 157:
		return "knet-cmp", true
	case 158:
		return "pcmail-srv", true
	case 159:
		return "nss-routing", true
	case 160:
		return "sgmp-traps", true
	case 161:
		return "snmp", true
	case 162:
		return "snmptrap", true
	case 163:
		return "cmip-man", true
	case 164:
		return "cmip-agent", true
	case 165:
		return "xns-courier", true
	case 166:
		return "s-net", true
	case 167:
		return "namp", true
	case 168:
		return "rsvd", true
	case 169:
		return "send", true
	case 170:
		return "print-srv", true
	case 171:
		return "multiplex", true
	case 172:
		return "cl-1", true
	case 173:
		return "xyplex-mux", true
	case 174:
		return "mailq", true
	case 175:
		return "vmnet", true
	case 176:
		return "genrad-mux", true
	case 177:
		return "xdmcp", true
	case 178:
		return "nextstep", true
	case 179:
		return "bgp", true
	case 180:
		return "ris", true
	case 181:
		return "unify", true
	case 182:
		return "audit", true
	case 183:
		return "ocbinder", true
	case 184:
		return "ocserver", true
	case 185:
		return "remote-kis", true
	case 186:
		return "kis", true
	case 187:
		return "aci", true
	case 188:
		return "mumps", true
	case 189:
		return "qft", true
	case 190:
		return "gacp", true
	case 191:
		return "prospero", true
	case 192:
		return "osu-nms", true
	case 193:
		return "srmp", true
	case 194:
		return "irc", true
	case 195:
		return "dn6-nlm-aud", true
	case 196:
		return "dn6-smm-red", true
	case 197:
		return "dls", true
	case 198:
		return "dls-mon", true
	case 199:
		return "smux", true
	case 200:
		return "src", true
	case 201:
		return "at-rtmp", true
	case 202:
		return "at-nbp", true
	case 203:
		return "at-3", true
	case 204:
		return "at-echo", true
	case 205:
		return "at-5", true
	case 206:
		return "at-zis", true
	case 207:
		return "at-7", true
	case 208:
		return "at-8", true
	case 209:
		return "qmtp", true
	case 210:
		return "z39-50", true
	case 211:
		return "914c-g", true
	case 212:
		return "anet", true
	case 213:
		return "ipx", true
	case 214:
		return "vmpwscs", true
	case 215:
		return "softpc", true
	case 216:
		return "CAIlic", true
	case 217:
		return "dbase", true
	case 218:
		return "mpp", true
	case 219:
		return "uarps", true
	case 220:
		return "imap3", true
	case 221:
		return "fln-spx", true
	case 222:
		return "rsh-spx", true
	case 223:
		return "cdc", true
	case 224:
		return "masqdialer", true
	case 242:
		return "direct", true
	case 243:
		return "sur-meas", true
	case 244:
		return "inbusiness", true
	case 245:
		return "link", true
	case 246:
		return "dsp3270", true
	case 247:
		return "subntbcst-tftp", true
	case 248:
		return "bhfhs", true
	case 256:
		return "rap", true
	case 257:
		return "set", true
	case 259:
		return "esro-gen", true
	case 260:
		return "openport", true
	case 261:
		return "nsiiops", true
	case 262:
		return "arcisdms", true
	case 263:
		return "hdap", true
	case 264:
		return "bgmp", true
	case 265:
		return "x-bone-ctl", true
	case 266:
		return "sst", true
	case 267:
		return "td-service", true
	case 268:
		return "td-replica", true
	case 269:
		return "manet", true
	case 271:
		return "pt-tls", true
	case 280:
		return "http-mgmt", true
	case 281:
		return "personal-link", true
	case 282:
		return "cableport-ax", true
	case 283:
		return "rescap", true
	case 284:
		return "corerjd", true
	case 286:
		return "fxp", true
	case 287:
		return "k-block", true
	case 308:
		return "novastorbakcup", true
	case 309:
		return "entrusttime", true
	case 310:
		return "bhmds", true
	case 311:
		return "asip-webadmin", true
	case 312:
		return "vslmp", true
	case 313:
		return "magenta-logic", true
	case 314:
		return "opalis-robot", true
	case 315:
		return "dpsi", true
	case 316:
		return "decauth", true
	case 317:
		return "zannet", true
	case 318:
		return "pkix-timestamp", true
	case 319:
		return "ptp-event", true
	case 320:
		return "ptp-general", true
	case 321:
		return "pip", true
	case 322:
		return "rtsps", true
	case 323:
		return "rpki-rtr", true
	case 324:
		return "rpki-rtr-tls", true
	case 333:
		return "texar", true
	case 344:
		return "pdap", true
	case 345:
		return "pawserv", true
	case 346:
		return "zserv", true
	case 347:
		return "fatserv", true
	case 348:
		return "csi-sgwp", true
	case 349:
		return "mftp", true
	case 350:
		return "matip-type-a", true
	case 351:
		return "matip-type-b", true
	case 352:
		return "dtag-ste-sb", true
	case 353:
		return "ndsauth", true
	case 354:
		return "bh611", true
	case 355:
		return "datex-asn", true
	case 356:
		return "cloanto-net-1", true
	case 357:
		return "bhevent", true
	case 358:
		return "shrinkwrap", true
	case 359:
		return "nsrmp", true
	case 360:
		return "scoi2odialog", true
	case 361:
		return "semantix", true
	case 362:
		return "srssend", true
	case 363:
		return "rsvp-tunnel", true
	case 364:
		return "aurora-cmgr", true
	case 365:
		return "dtk", true
	case 366:
		return "odmr", true
	case 367:
		return "mortgageware", true
	case 368:
		return "qbikgdp", true
	case 369:
		return "rpc2portmap", true
	case 370:
		return "codaauth2", true
	case 371:
		return "clearcase", true
	case 372:
		return "ulistproc", true
	case 373:
		return "legent-1", true
	case 374:
		return "legent-2", true
	case 375:
		return "hassle", true
	case 376:
		return "nip", true
	case 377:
		return "tnETOS", true
	case 378:
		return "dsETOS", true
	case 379:
		return "is99c", true
	case 380:
		return "is99s", true
	case 381:
		return "hp-collector", true
	case 382:
		return "hp-managed-node", true
	case 383:
		return "hp-alarm-mgr", true
	case 384:
		return "arns", true
	case 385:
		return "ibm-app", true
	case 386:
		return "asa", true
	case 387:
		return "aurp", true
	case 388:
		return "unidata-ldm", true
	case 389:
		return "ldap", true
	case 390:
		return "uis", true
	case 391:
		return "synotics-relay", true
	case 392:
		return "synotics-broker", true
	case 393:
		return "meta5", true
	case 394:
		return "embl-ndt", true
	case 395:
		return "netcp", true
	case 396:
		return "netware-ip", true
	case 397:
		return "mptn", true
	case 398:
		return "kryptolan", true
	case 399:
		return "iso-tsap-c2", true
	case 400:
		return "osb-sd", true
	case 401:
		return "ups", true
	case 402:
		return "genie", true
	case 403:
		return "decap", true
	case 404:
		return "nced", true
	case 405:
		return "ncld", true
	case 406:
		return "imsp", true
	case 407:
		return "timbuktu", true
	case 408:
		return "prm-sm", true
	case 409:
		return "prm-nm", true
	case 410:
		return "decladebug", true
	case 411:
		return "rmt", true
	case 412:
		return "synoptics-trap", true
	case 413:
		return "smsp", true
	case 414:
		return "infoseek", true
	case 415:
		return "bnet", true
	case 416:
		return "silverplatter", true
	case 417:
		return "onmux", true
	case 418:
		return "hyper-g", true
	case 419:
		return "ariel1", true
	case 420:
		return "smpte", true
	case 421:
		return "ariel2", true
	case 422:
		return "ariel3", true
	case 423:
		return "opc-job-start", true
	case 424:
		return "opc-job-track", true
	case 425:
		return "icad-el", true
	case 426:
		return "smartsdp", true
	case 427:
		return "svrloc", true
	case 428:
		return "ocs-cmu", true
	case 429:
		return "ocs-amu", true
	case 430:
		return "utmpsd", true
	case 431:
		return "utmpcd", true
	case 432:
		return "iasd", true
	case 433:
		return "nnsp", true
	case 434:
		return "mobileip-agent", true
	case 435:
		return "mobilip-mn", true
	case 436:
		return "dna-cml", true
	case 437:
		return "comscm", true
	case 438:
		return "dsfgw", true
	case 439:
		return "dasp", true
	case 440:
		return "sgcp", true
	case 441:
		return "decvms-sysmgt", true
	case 442:
		return "cvc-hostd", true
	case 443:
		return "https", true
	case 444:
		return "snpp", true
	case 445:
		return "microsoft-ds", true
	case 446:
		return "ddm-rdb", true
	case 447:
		return "ddm-dfm", true
	case 448:
		return "ddm-ssl", true
	case 449:
		return "as-servermap", true
	case 450:
		return "tserver", true
	case 451:
		return "sfs-smp-net", true
	case 452:
		return "sfs-config", true
	case 453:
		return "creativeserver", true
	case 454:
		return "contentserver", true
	case 455:
		return "creativepartnr", true
	case 456:
		return "macon-tcp", true
	case 457:
		return "scohelp", true
	case 458:
		return "appleqtc", true
	case 459:
		return "ampr-rcmd", true
	case 460:
		return "skronk", true
	case 461:
		return "datasurfsrv", true
	case 462:
		return "datasurfsrvsec", true
	case 463:
		return "alpes", true
	case 464:
		return "kpasswd", true
	case 465:
		return "urd", true
	case 466:
		return "digital-vrc", true
	case 467:
		return "mylex-mapd", true
	case 468:
		return "photuris", true
	case 469:
		return "rcp", true
	case 470:
		return "scx-proxy", true
	case 471:
		return "mondex", true
	case 472:
		return "ljk-login", true
	case 473:
		return "hybrid-pop", true
	case 474:
		return "tn-tl-w1", true
	case 475:
		return "tcpnethaspsrv", true
	case 476:
		return "tn-tl-fd1", true
	case 477:
		return "ss7ns", true
	case 478:
		return "spsc", true
	case 479:
		return "iafserver", true
	case 480:
		return "iafdbase", true
	case 481:
		return "ph", true
	case 482:
		return "bgs-nsi", true
	case 483:
		return "ulpnet", true
	case 484:
		return "integra-sme", true
	case 485:
		return "powerburst", true
	case 486:
		return "avian", true
	case 487:
		return "saft", true
	case 488:
		return "gss-http", true
	case 489:
		return "nest-protocol", true
	case 490:
		return "micom-pfs", true
	case 491:
		return "go-login", true
	case 492:
		return "ticf-1", true
	case 493:
		return "ticf-2", true
	case 494:
		return "pov-ray", true
	case 495:
		return "intecourier", true
	case 496:
		return "pim-rp-disc", true
	case 497:
		return "retrospect", true
	case 498:
		return "siam", true
	case 499:
		return "iso-ill", true
	case 500:
		return "isakmp", true
	case 501:
		return "stmf", true
	case 502:
		return "mbap", true
	case 503:
		return "intrinsa", true
	case 504:
		return "citadel", true
	case 505:
		return "mailbox-lm", true
	case 506:
		return "ohimsrv", true
	case 507:
		return "crs", true
	case 508:
		return "xvttp", true
	case 509:
		return "snare", true
	case 510:
		return "fcp", true
	case 511:
		return "passgo", true
	case 512:
		return "exec", true
	case 513:
		return "login", true
	case 514:
		return "shell", true
	case 515:
		return "printer", true
	case 516:
		return "videotex", true
	case 517:
		return "talk", true
	case 518:
		return "ntalk", true
	case 519:
		return "utime", true
	case 520:
		return "efs", true
	case 521:
		return "ripng", true
	case 522:
		return "ulp", true
	case 523:
		return "ibm-db2", true
	case 524:
		return "ncp", true
	case 525:
		return "timed", true
	case 526:
		return "tempo", true
	case 527:
		return "stx", true
	case 528:
		return "custix", true
	case 529:
		return "irc-serv", true
	case 530:
		return "courier", true
	case 531:
		return "conference", true
	case 532:
		return "netnews", true
	case 533:
		return "netwall", true
	case 534:
		return "windream", true
	case 535:
		return "iiop", true
	case 536:
		return "opalis-rdv", true
	case 537:
		return "nmsp", true
	case 538:
		return "gdomap", true
	case 539:
		return "apertus-ldp", true
	case 540:
		return "uucp", true
	case 541:
		return "uucp-rlogin", true
	case 542:
		return "commerce", true
	case 543:
		return "klogin", true
	case 544:
		return "kshell", true
	case 545:
		return "appleqtcsrvr", true
	case 546:
		return "dhcpv6-client", true
	case 547:
		return "dhcpv6-server", true
	case 548:
		return "afpovertcp", true
	case 549:
		return "idfp", true
	case 550:
		return "new-rwho", true
	case 551:
		return "cybercash", true
	case 552:
		return "devshr-nts", true
	case 553:
		return "pirp", true
	case 554:
		return "rtsp", true
	case 555:
		return "dsf", true
	case 556:
		return "remotefs", true
	case 557:
		return "openvms-sysipc", true
	case 558:
		return "sdnskmp", true
	case 559:
		return "teedtap", true
	case 560:
		return "rmonitor", true
	case 561:
		return "monitor", true
	case 562:
		return "chshell", true
	case 563:
		return "nntps", true
	case 564:
		return "9pfs", true
	case 565:
		return "whoami", true
	case 566:
		return "streettalk", true
	case 567:
		return "banyan-rpc", true
	case 568:
		return "ms-shuttle", true
	case 569:
		return "ms-rome", true
	case 570:
		return "meter", true
	case 571:
		return "meter", true
	case 572:
		return "sonar", true
	case 573:
		return "banyan-vip", true
	case 574:
		return "ftp-agent", true
	case 575:
		return "vemmi", true
	case 576:
		return "ipcd", true
	case 577:
		return "vnas", true
	case 578:
		return "ipdd", true
	case 579:
		return "decbsrv", true
	case 580:
		return "sntp-heartbeat", true
	case 581:
		return "bdp", true
	case 582:
		return "scc-security", true
	case 583:
		return "philips-vc", true
	case 584:
		return "keyserver", true
	case 586:
		return "password-chg", true
	case 587:
		return "submission", true
	case 588:
		return "cal", true
	case 589:
		return "eyelink", true
	case 590:
		return "tns-cml", true
	case 591:
		return "http-alt", true
	case 592:
		return "eudora-set", true
	case 593:
		return "http-rpc-epmap", true
	case 594:
		return "tpip", true
	case 595:
		return "cab-protocol", true
	case 596:
		return "smsd", true
	case 597:
		return "ptcnameservice", true
	case 598:
		return "sco-websrvrmg3", true
	case 599:
		return "acp", true
	case 600:
		return "ipcserver", true
	case 601:
		return "syslog-conn", true
	case 602:
		return "xmlrpc-beep", true
	case 603:
		return "idxp", true
	case 604:
		return "tunnel", true
	case 605:
		return "soap-beep", true
	case 606:
		return "urm", true
	case 607:
		return "nqs", true
	case 608:
		return "sift-uft", true
	case 609:
		return "npmp-trap", true
	case 610:
		return "npmp-local", true
	case 611:
		return "npmp-gui", true
	case 612:
		return "hmmp-ind", true
	case 613:
		return "hmmp-op", true
	case 614:
		return "sshell", true
	case 615:
		return "sco-inetmgr", true
	case 616:
		return "sco-sysmgr", true
	case 617:
		return "sco-dtmgr", true
	case 618:
		return "dei-icda", true
	case 619:
		return "compaq-evm", true
	case 620:
		return "sco-websrvrmgr", true
	case 621:
		return "escp-ip", true
	case 622:
		return "collaborator", true
	case 623:
		return "oob-ws-http", true
	case 624:
		return "cryptoadmin", true
	case 625:
		return "dec-dlm", true
	case 626:
		return "asia", true
	case 627:
		return "passgo-tivoli", true
	case 628:
		return "qmqp", true
	case 629:
		return "3com-amp3", true
	case 630:
		return "rda", true
	case 631:
		return "ipp", true
	case 632:
		return "bmpp", true
	case 633:
		return "servstat", true
	case 634:
		return "ginad", true
	case 635:
		return "rlzdbase", true
	case 636:
		return "ldaps", true
	case 637:
		return "lanserver", true
	case 638:
		return "mcns-sec", true
	case 639:
		return "msdp", true
	case 640:
		return "entrust-sps", true
	case 641:
		return "repcmd", true
	case 642:
		return "esro-emsdp", true
	case 643:
		return "sanity", true
	case 644:
		return "dwr", true
	case 645:
		return "pssc", true
	case 646:
		return "ldp", true
	case 647:
		return "dhcp-failover", true
	case 648:
		return "rrp", true
	case 649:
		return "cadview-3d", true
	case 650:
		return "obex", true
	case 651:
		return "ieee-mms", true
	case 652:
		return "hello-port", true
	case 653:
		return "repscmd", true
	case 654:
		return "aodv", true
	case 655:
		return "tinc", true
	case 656:
		return "spmp", true
	case 657:
		return "rmc", true
	case 658:
		return "tenfold", true
	case 660:
		return "mac-srvr-admin", true
	case 661:
		return "hap", true
	case 662:
		return "pftp", true
	case 663:
		return "purenoise", true
	case 664:
		return "oob-ws-https", true
	case 665:
		return "sun-dr", true
	case 666:
		return "mdqs", true
	case 667:
		return "disclose", true
	case 668:
		return "mecomm", true
	case 669:
		return "meregister", true
	case 670:
		return "vacdsm-sws", true
	case 671:
		return "vacdsm-app", true
	case 672:
		return "vpps-qua", true
	case 673:
		return "cimplex", true
	case 674:
		return "acap", true
	case 675:
		return "dctp", true
	case 676:
		return "vpps-via", true
	case 677:
		return "vpp", true
	case 678:
		return "ggf-ncp", true
	case 679:
		return "mrm", true
	case 680:
		return "entrust-aaas", true
	case 681:
		return "entrust-aams", true
	case 682:
		return "xfr", true
	case 683:
		return "corba-iiop", true
	case 684:
		return "corba-iiop-ssl", true
	case 685:
		return "mdc-portmapper", true
	case 686:
		return "hcp-wismar", true
	case 687:
		return "asipregistry", true
	case 688:
		return "realm-rusd", true
	case 689:
		return "nmap", true
	case 690:
		return "vatp", true
	case 691:
		return "msexch-routing", true
	case 692:
		return "hyperwave-isp", true
	case 693:
		return "connendp", true
	case 694:
		return "ha-cluster", true
	case 695:
		return "ieee-mms-ssl", true
	case 696:
		return "rushd", true
	case 697:
		return "uuidgen", true
	case 698:
		return "olsr", true
	case 699:
		return "accessnetwork", true
	case 700:
		return "epp", true
	case 701:
		return "lmp", true
	case 702:
		return "iris-beep", true
	case 704:
		return "elcsd", true
	case 705:
		return "agentx", true
	case 706:
		return "silc", true
	case 707:
		return "borland-dsj", true
	case 709:
		return "entrust-kmsh", true
	case 710:
		return "entrust-ash", true
	case 711:
		return "cisco-tdp", true
	case 712:
		return "tbrpf", true
	case 713:
		return "iris-xpc", true
	case 714:
		return "iris-xpcs", true
	case 715:
		return "iris-lwz", true
	case 729:
		return "netviewdm1", true
	case 730:
		return "netviewdm2", true
	case 731:
		return "netviewdm3", true
	case 741:
		return "netgw", true
	case 742:
		return "netrcs", true
	case 744:
		return "flexlm", true
	case 747:
		return "fujitsu-dev", true
	case 748:
		return "ris-cm", true
	case 749:
		return "kerberos-adm", true
	case 750:
		return "rfile", true
	case 751:
		return "pump", true
	case 752:
		return "qrh", true
	case 753:
		return "rrh", true
	case 754:
		return "tell", true
	case 758:
		return "nlogin", true
	case 759:
		return "con", true
	case 760:
		return "ns", true
	case 761:
		return "rxe", true
	case 762:
		return "quotad", true
	case 763:
		return "cycleserv", true
	case 764:
		return "omserv", true
	case 765:
		return "webster", true
	case 767:
		return "phonebook", true
	case 769:
		return "vid", true
	case 770:
		return "cadlock", true
	case 771:
		return "rtip", true
	case 772:
		return "cycleserv2", true
	case 773:
		return "submit", true
	case 774:
		return "rpasswd", true
	case 775:
		return "entomb", true
	case 776:
		return "wpages", true
	case 777:
		return "multiling-http", true
	case 780:
		return "wpgs", true
	case 800:
		return "mdbs-daemon", true
	case 801:
		return "device", true
	case 802:
		return "mbap-s", true
	case 810:
		return "fcp-udp", true
	case 828:
		return "itm-mcell-s", true
	case 829:
		return "pkix-3-ca-ra", true
	case 830:
		return "netconf-ssh", true
	case 831:
		return "netconf-beep", true
	case 832:
		return "netconfsoaphttp", true
	case 833:
		return "netconfsoapbeep", true
	case 847:
		return "dhcp-failover2", true
	case 848:
		return "gdoi", true
	case 853:
		return "domain-s", true
	case 854:
		return "dlep", true
	case 860:
		return "iscsi", true
	case 861:
		return "owamp-control", true
	case 862:
		return "twamp-control", true
	case 873:
		return "rsync", true
	case 886:
		return "iclcnet-locate", true
	case 887:
		return "iclcnet-svinfo", true
	case 888:
		return "accessbuilder", true
	case 900:
		return "omginitialrefs", true
	case 901:
		return "smpnameres", true
	case 902:
		return "ideafarm-door", true
	case 903:
		return "ideafarm-panic", true
	case 910:
		return "kink", true
	case 911:
		return "xact-backup", true
	case 912:
		return "apex-mesh", true
	case 913:
		return "apex-edge", true
	case 953:
		return "rndc", true
	case 989:
		return "ftps-data", true
	case 990:
		return "ftps", true
	case 991:
		return "nas", true
	case 992:
		return "telnets", true
	case 993:
		return "imaps", true
	case 995:
		return "pop3s", true
	case 996:
		return "vsinet", true
	case 997:
		return "maitrd", true
	case 998:
		return "busboy", true
	case 999:
		return "garcon", true
	case 1000:
		return "cadlock2", true
	case 1001:
		return "webpush", true
	case 1010:
		return "surf", true
	case 1021:
		return "exp1", true
	case 1022:
		return "exp2", true
	case 1025:
		return "blackjack", true
	case 1026:
		return "cap", true
	case 1029:
		return "solid-mux", true
	case 1033:
		return "netinfo-local", true
	case 1034:
		return "activesync", true
	case 1035:
		return "mxxrlogin", true
	case 1036:
		return "nsstp", true
	case 1037:
		return "ams", true
	case 1038:
		return "mtqp", true
	case 1039:
		return "sbl", true
	case 1040:
		return "netarx", true
	case 1041:
		return "danf-ak2", true
	case 1042:
		return "afrog", true
	case 1043:
		return "boinc-client", true
	case 1044:
		return "dcutility", true
	case 1045:
		return "fpitp", true
	case 1046:
		return "wfremotertm", true
	case 1047:
		return "neod1", true
	case 1048:
		return "neod2", true
	case 1049:
		return "td-postman", true
	case 1050:
		return "cma", true
	case 1051:
		return "optima-vnet", true
	case 1052:
		return "ddt", true
	case 1053:
		return "remote-as", true
	case 1054:
		return "brvread", true
	case 1055:
		return "ansyslmd", true
	case 1056:
		return "vfo", true
	case 1057:
		return "startron", true
	case 1058:
		return "nim", true
	case 1059:
		return "nimreg", true
	case 1060:
		return "polestar", true
	case 1061:
		return "kiosk", true
	case 1062:
		return "veracity", true
	case 1063:
		return "kyoceranetdev", true
	case 1064:
		return "jstel", true
	case 1065:
		return "syscomlan", true
	case 1066:
		return "fpo-fns", true
	case 1067:
		return "instl-boots", true
	case 1068:
		return "instl-bootc", true
	case 1069:
		return "cognex-insight", true
	case 1070:
		return "gmrupdateserv", true
	case 1071:
		return "bsquare-voip", true
	case 1072:
		return "cardax", true
	case 1073:
		return "bridgecontrol", true
	case 1074:
		return "warmspotMgmt", true
	case 1075:
		return "rdrmshc", true
	case 1076:
		return "dab-sti-c", true
	case 1077:
		return "imgames", true
	case 1078:
		return "avocent-proxy", true
	case 1079:
		return "asprovatalk", true
	case 1080:
		return "socks", true
	case 1081:
		return "pvuniwien", true
	case 1082:
		return "amt-esd-prot", true
	case 1083:
		return "ansoft-lm-1", true
	case 1084:
		return "ansoft-lm-2", true
	case 1085:
		return "webobjects", true
	case 1086:
		return "cplscrambler-lg", true
	case 1087:
		return "cplscrambler-in", true
	case 1088:
		return "cplscrambler-al", true
	case 1089:
		return "ff-annunc", true
	case 1090:
		return "ff-fms", true
	case 1091:
		return "ff-sm", true
	case 1092:
		return "obrpd", true
	case 1093:
		return "proofd", true
	case 1094:
		return "rootd", true
	case 1095:
		return "nicelink", true
	case 1096:
		return "cnrprotocol", true
	case 1097:
		return "sunclustermgr", true
	case 1098:
		return "rmiactivation", true
	case 1099:
		return "rmiregistry", true
	case 1100:
		return "mctp", true
	case 1101:
		return "pt2-discover", true
	case 1102:
		return "adobeserver-1", true
	case 1103:
		return "adobeserver-2", true
	case 1104:
		return "xrl", true
	case 1105:
		return "ftranhc", true
	case 1106:
		return "isoipsigport-1", true
	case 1107:
		return "isoipsigport-2", true
	case 1108:
		return "ratio-adp", true
	case 1110:
		return "webadmstart", true
	case 1111:
		return "lmsocialserver", true
	case 1112:
		return "icp", true
	case 1113:
		return "ltp-deepspace", true
	case 1114:
		return "mini-sql", true
	case 1115:
		return "ardus-trns", true
	case 1116:
		return "ardus-cntl", true
	case 1117:
		return "ardus-mtrns", true
	case 1118:
		return "sacred", true
	case 1119:
		return "bnetgame", true
	case 1120:
		return "bnetfile", true
	case 1121:
		return "rmpp", true
	case 1122:
		return "availant-mgr", true
	case 1123:
		return "murray", true
	case 1124:
		return "hpvmmcontrol", true
	case 1125:
		return "hpvmmagent", true
	case 1126:
		return "hpvmmdata", true
	case 1127:
		return "kwdb-commn", true
	case 1128:
		return "saphostctrl", true
	case 1129:
		return "saphostctrls", true
	case 1130:
		return "casp", true
	case 1131:
		return "caspssl", true
	case 1132:
		return "kvm-via-ip", true
	case 1133:
		return "dfn", true
	case 1134:
		return "aplx", true
	case 1135:
		return "omnivision", true
	case 1136:
		return "hhb-gateway", true
	case 1137:
		return "trim", true
	case 1138:
		return "encrypted-admin", true
	case 1139:
		return "evm", true
	case 1140:
		return "autonoc", true
	case 1141:
		return "mxomss", true
	case 1142:
		return "edtools", true
	case 1143:
		return "imyx", true
	case 1144:
		return "fuscript", true
	case 1145:
		return "x9-icue", true
	case 1146:
		return "audit-transfer", true
	case 1147:
		return "capioverlan", true
	case 1148:
		return "elfiq-repl", true
	case 1149:
		return "bvtsonar", true
	case 1150:
		return "blaze", true
	case 1151:
		return "unizensus", true
	case 1152:
		return "winpoplanmess", true
	case 1153:
		return "c1222-acse", true
	case 1154:
		return "resacommunity", true
	case 1155:
		return "nfa", true
	case 1156:
		return "iascontrol-oms", true
	case 1157:
		return "iascontrol", true
	case 1158:
		return "dbcontrol-oms", true
	case 1159:
		return "oracle-oms", true
	case 1160:
		return "olsv", true
	case 1161:
		return "health-polling", true
	case 1162:
		return "health-trap", true
	case 1163:
		return "sddp", true
	case 1164:
		return "qsm-proxy", true
	case 1165:
		return "qsm-gui", true
	case 1166:
		return "qsm-remote", true
	case 1167:
		return "cisco-ipsla", true
	case 1168:
		return "vchat", true
	case 1169:
		return "tripwire", true
	case 1170:
		return "atc-lm", true
	case 1171:
		return "atc-appserver", true
	case 1172:
		return "dnap", true
	case 1173:
		return "d-cinema-rrp", true
	case 1174:
		return "fnet-remote-ui", true
	case 1175:
		return "dossier", true
	case 1176:
		return "indigo-server", true
	case 1177:
		return "dkmessenger", true
	case 1178:
		return "sgi-storman", true
	case 1179:
		return "b2n", true
	case 1180:
		return "mc-client", true
	case 1181:
		return "3comnetman", true
	case 1182:
		return "accelenet", true
	case 1183:
		return "llsurfup-http", true
	case 1184:
		return "llsurfup-https", true
	case 1185:
		return "catchpole", true
	case 1186:
		return "mysql-cluster", true
	case 1187:
		return "alias", true
	case 1188:
		return "hp-webadmin", true
	case 1189:
		return "unet", true
	case 1190:
		return "commlinx-avl", true
	case 1191:
		return "gpfs", true
	case 1192:
		return "caids-sensor", true
	case 1193:
		return "fiveacross", true
	case 1194:
		return "openvpn", true
	case 1195:
		return "rsf-1", true
	case 1196:
		return "netmagic", true
	case 1197:
		return "carrius-rshell", true
	case 1198:
		return "cajo-discovery", true
	case 1199:
		return "dmidi", true
	case 1200:
		return "scol", true
	case 1201:
		return "nucleus-sand", true
	case 1202:
		return "caiccipc", true
	case 1203:
		return "ssslic-mgr", true
	case 1204:
		return "ssslog-mgr", true
	case 1205:
		return "accord-mgc", true
	case 1206:
		return "anthony-data", true
	case 1207:
		return "metasage", true
	case 1208:
		return "seagull-ais", true
	case 1209:
		return "ipcd3", true
	case 1210:
		return "eoss", true
	case 1211:
		return "groove-dpp", true
	case 1212:
		return "lupa", true
	case 1213:
		return "mpc-lifenet", true
	case 1214:
		return "kazaa", true
	case 1215:
		return "scanstat-1", true
	case 1216:
		return "etebac5", true
	case 1217:
		return "hpss-ndapi", true
	case 1218:
		return "aeroflight-ads", true
	case 1219:
		return "aeroflight-ret", true
	case 1220:
		return "qt-serveradmin", true
	case 1221:
		return "sweetware-apps", true
	case 1222:
		return "nerv", true
	case 1223:
		return "tgp", true
	case 1224:
		return "vpnz", true
	case 1225:
		return "slinkysearch", true
	case 1226:
		return "stgxfws", true
	case 1227:
		return "dns2go", true
	case 1228:
		return "florence", true
	case 1229:
		return "zented", true
	case 1230:
		return "periscope", true
	case 1231:
		return "menandmice-lpm", true
	case 1232:
		return "first-defense", true
	case 1233:
		return "univ-appserver", true
	case 1234:
		return "search-agent", true
	case 1235:
		return "mosaicsyssvc1", true
	case 1236:
		return "bvcontrol", true
	case 1237:
		return "tsdos390", true
	case 1238:
		return "hacl-qs", true
	case 1239:
		return "nmsd", true
	case 1240:
		return "instantia", true
	case 1241:
		return "nessus", true
	case 1242:
		return "nmasoverip", true
	case 1243:
		return "serialgateway", true
	case 1244:
		return "isbconference1", true
	case 1245:
		return "isbconference2", true
	case 1246:
		return "payrouter", true
	case 1247:
		return "visionpyramid", true
	case 1248:
		return "hermes", true
	case 1249:
		return "mesavistaco", true
	case 1250:
		return "swldy-sias", true
	case 1251:
		return "servergraph", true
	case 1252:
		return "bspne-pcc", true
	case 1253:
		return "q55-pcc", true
	case 1254:
		return "de-noc", true
	case 1255:
		return "de-cache-query", true
	case 1256:
		return "de-server", true
	case 1257:
		return "shockwave2", true
	case 1258:
		return "opennl", true
	case 1259:
		return "opennl-voice", true
	case 1260:
		return "ibm-ssd", true
	case 1261:
		return "mpshrsv", true
	case 1262:
		return "qnts-orb", true
	case 1263:
		return "dka", true
	case 1264:
		return "prat", true
	case 1265:
		return "dssiapi", true
	case 1266:
		return "dellpwrappks", true
	case 1267:
		return "epc", true
	case 1268:
		return "propel-msgsys", true
	case 1269:
		return "watilapp", true
	case 1270:
		return "opsmgr", true
	case 1271:
		return "excw", true
	case 1272:
		return "cspmlockmgr", true
	case 1273:
		return "emc-gateway", true
	case 1274:
		return "t1distproc", true
	case 1275:
		return "ivcollector", true
	case 1277:
		return "miva-mqs", true
	case 1278:
		return "dellwebadmin-1", true
	case 1279:
		return "dellwebadmin-2", true
	case 1280:
		return "pictrography", true
	case 1281:
		return "healthd", true
	case 1282:
		return "emperion", true
	case 1283:
		return "productinfo", true
	case 1284:
		return "iee-qfx", true
	case 1285:
		return "neoiface", true
	case 1286:
		return "netuitive", true
	case 1287:
		return "routematch", true
	case 1288:
		return "navbuddy", true
	case 1289:
		return "jwalkserver", true
	case 1290:
		return "winjaserver", true
	case 1291:
		return "seagulllms", true
	case 1292:
		return "dsdn", true
	case 1293:
		return "pkt-krb-ipsec", true
	case 1294:
		return "cmmdriver", true
	case 1295:
		return "ehtp", true
	case 1296:
		return "dproxy", true
	case 1297:
		return "sdproxy", true
	case 1298:
		return "lpcp", true
	case 1299:
		return "hp-sci", true
	case 1300:
		return "h323hostcallsc", true
	case 1303:
		return "sftsrv", true
	case 1304:
		return "boomerang", true
	case 1305:
		return "pe-mike", true
	case 1306:
		return "re-conn-proto", true
	case 1307:
		return "pacmand", true
	case 1308:
		return "odsi", true
	case 1309:
		return "jtag-server", true
	case 1310:
		return "husky", true
	case 1311:
		return "rxmon", true
	case 1312:
		return "sti-envision", true
	case 1313:
		return "bmc-patroldb", true
	case 1314:
		return "pdps", true
	case 1315:
		return "els", true
	case 1316:
		return "exbit-escp", true
	case 1317:
		return "vrts-ipcserver", true
	case 1318:
		return "krb5gatekeeper", true
	case 1319:
		return "amx-icsp", true
	case 1320:
		return "amx-axbnet", true
	case 1321:
		return "pip", true
	case 1322:
		return "novation", true
	case 1323:
		return "brcd", true
	case 1324:
		return "delta-mcp", true
	case 1325:
		return "dx-instrument", true
	case 1326:
		return "wimsic", true
	case 1327:
		return "ultrex", true
	case 1328:
		return "ewall", true
	case 1329:
		return "netdb-export", true
	case 1330:
		return "streetperfect", true
	case 1331:
		return "intersan", true
	case 1332:
		return "pcia-rxp-b", true
	case 1333:
		return "passwrd-policy", true
	case 1334:
		return "writesrv", true
	case 1335:
		return "digital-notary", true
	case 1336:
		return "ischat", true
	case 1337:
		return "menandmice-dns", true
	case 1338:
		return "wmc-log-svc", true
	case 1339:
		return "kjtsiteserver", true
	case 1340:
		return "naap", true
	case 1341:
		return "qubes", true
	case 1342:
		return "esbroker", true
	case 1343:
		return "re101", true
	case 1344:
		return "icap", true
	case 1345:
		return "vpjp", true
	case 1346:
		return "alta-ana-lm", true
	case 1347:
		return "bbn-mmc", true
	case 1348:
		return "bbn-mmx", true
	case 1349:
		return "sbook", true
	case 1350:
		return "editbench", true
	case 1351:
		return "equationbuilder", true
	case 1352:
		return "lotusnote", true
	case 1353:
		return "relief", true
	case 1354:
		return "XSIP-network", true
	case 1355:
		return "intuitive-edge", true
	case 1356:
		return "cuillamartin", true
	case 1357:
		return "pegboard", true
	case 1358:
		return "connlcli", true
	case 1359:
		return "ftsrv", true
	case 1360:
		return "mimer", true
	case 1361:
		return "linx", true
	case 1362:
		return "timeflies", true
	case 1363:
		return "ndm-requester", true
	case 1364:
		return "ndm-server", true
	case 1365:
		return "adapt-sna", true
	case 1366:
		return "netware-csp", true
	case 1367:
		return "dcs", true
	case 1368:
		return "screencast", true
	case 1369:
		return "gv-us", true
	case 1370:
		return "us-gv", true
	case 1371:
		return "fc-cli", true
	case 1372:
		return "fc-ser", true
	case 1373:
		return "chromagrafx", true
	case 1374:
		return "molly", true
	case 1375:
		return "bytex", true
	case 1376:
		return "ibm-pps", true
	case 1377:
		return "cichlid", true
	case 1378:
		return "elan", true
	case 1379:
		return "dbreporter", true
	case 1380:
		return "telesis-licman", true
	case 1381:
		return "apple-licman", true
	case 1382:
		return "udt-os", true
	case 1383:
		return "gwha", true
	case 1384:
		return "os-licman", true
	case 1385:
		return "atex-elmd", true
	case 1386:
		return "checksum", true
	case 1387:
		return "cadsi-lm", true
	case 1388:
		return "objective-dbc", true
	case 1389:
		return "iclpv-dm", true
	case 1390:
		return "iclpv-sc", true
	case 1391:
		return "iclpv-sas", true
	case 1392:
		return "iclpv-pm", true
	case 1393:
		return "iclpv-nls", true
	case 1394:
		return "iclpv-nlc", true
	case 1395:
		return "iclpv-wsm", true
	case 1396:
		return "dvl-activemail", true
	case 1397:
		return "audio-activmail", true
	case 1398:
		return "video-activmail", true
	case 1399:
		return "cadkey-licman", true
	case 1400:
		return "cadkey-tablet", true
	case 1401:
		return "goldleaf-licman", true
	case 1402:
		return "prm-sm-np", true
	case 1403:
		return "prm-nm-np", true
	case 1404:
		return "igi-lm", true
	case 1405:
		return "ibm-res", true
	case 1406:
		return "netlabs-lm", true
	case 1407:
		return "tibet-server", true
	case 1408:
		return "sophia-lm", true
	case 1409:
		return "here-lm", true
	case 1410:
		return "hiq", true
	case 1411:
		return "af", true
	case 1412:
		return "innosys", true
	case 1413:
		return "innosys-acl", true
	case 1414:
		return "ibm-mqseries", true
	case 1415:
		return "dbstar", true
	case 1416:
		return "novell-lu6-2", true
	case 1417:
		return "timbuktu-srv1", true
	case 1418:
		return "timbuktu-srv2", true
	case 1419:
		return "timbuktu-srv3", true
	case 1420:
		return "timbuktu-srv4", true
	case 1421:
		return "gandalf-lm", true
	case 1422:
		return "autodesk-lm", true
	case 1423:
		return "essbase", true
	case 1424:
		return "hybrid", true
	case 1425:
		return "zion-lm", true
	case 1426:
		return "sais", true
	case 1427:
		return "mloadd", true
	case 1428:
		return "informatik-lm", true
	case 1429:
		return "nms", true
	case 1430:
		return "tpdu", true
	case 1431:
		return "rgtp", true
	case 1432:
		return "blueberry-lm", true
	case 1433:
		return "ms-sql-s", true
	case 1434:
		return "ms-sql-m", true
	case 1435:
		return "ibm-cics", true
	case 1436:
		return "saism", true
	case 1437:
		return "tabula", true
	case 1438:
		return "eicon-server", true
	case 1439:
		return "eicon-x25", true
	case 1440:
		return "eicon-slp", true
	case 1441:
		return "cadis-1", true
	case 1442:
		return "cadis-2", true
	case 1443:
		return "ies-lm", true
	case 1444:
		return "marcam-lm", true
	case 1445:
		return "proxima-lm", true
	case 1446:
		return "ora-lm", true
	case 1447:
		return "apri-lm", true
	case 1448:
		return "oc-lm", true
	case 1449:
		return "peport", true
	case 1450:
		return "dwf", true
	case 1451:
		return "infoman", true
	case 1452:
		return "gtegsc-lm", true
	case 1453:
		return "genie-lm", true
	case 1454:
		return "interhdl-elmd", true
	case 1455:
		return "esl-lm", true
	case 1456:
		return "dca", true
	case 1457:
		return "valisys-lm", true
	case 1458:
		return "nrcabq-lm", true
	case 1459:
		return "proshare1", true
	case 1460:
		return "proshare2", true
	case 1461:
		return "ibm-wrless-lan", true
	case 1462:
		return "world-lm", true
	case 1463:
		return "nucleus", true
	case 1464:
		return "msl-lmd", true
	case 1465:
		return "pipes", true
	case 1466:
		return "oceansoft-lm", true
	case 1467:
		return "csdmbase", true
	case 1468:
		return "csdm", true
	case 1469:
		return "aal-lm", true
	case 1470:
		return "uaiact", true
	case 1471:
		return "csdmbase", true
	case 1472:
		return "csdm", true
	case 1473:
		return "openmath", true
	case 1474:
		return "telefinder", true
	case 1475:
		return "taligent-lm", true
	case 1476:
		return "clvm-cfg", true
	case 1477:
		return "ms-sna-server", true
	case 1478:
		return "ms-sna-base", true
	case 1479:
		return "dberegister", true
	case 1480:
		return "pacerforum", true
	case 1481:
		return "airs", true
	case 1482:
		return "miteksys-lm", true
	case 1483:
		return "afs", true
	case 1484:
		return "confluent", true
	case 1485:
		return "lansource", true
	case 1486:
		return "nms-topo-serv", true
	case 1487:
		return "localinfosrvr", true
	case 1488:
		return "docstor", true
	case 1489:
		return "dmdocbroker", true
	case 1490:
		return "insitu-conf", true
	case 1492:
		return "stone-design-1", true
	case 1493:
		return "netmap-lm", true
	case 1494:
		return "ica", true
	case 1495:
		return "cvc", true
	case 1496:
		return "liberty-lm", true
	case 1497:
		return "rfx-lm", true
	case 1498:
		return "sybase-sqlany", true
	case 1499:
		return "fhc", true
	case 1500:
		return "vlsi-lm", true
	case 1501:
		return "saiscm", true
	case 1502:
		return "shivadiscovery", true
	case 1503:
		return "imtc-mcs", true
	case 1504:
		return "evb-elm", true
	case 1505:
		return "funkproxy", true
	case 1506:
		return "utcd", true
	case 1507:
		return "symplex", true
	case 1508:
		return "diagmond", true
	case 1509:
		return "robcad-lm", true
	case 1510:
		return "mvx-lm", true
	case 1511:
		return "3l-l1", true
	case 1512:
		return "wins", true
	case 1513:
		return "fujitsu-dtc", true
	case 1514:
		return "fujitsu-dtcns", true
	case 1515:
		return "ifor-protocol", true
	case 1516:
		return "vpad", true
	case 1517:
		return "vpac", true
	case 1518:
		return "vpvd", true
	case 1519:
		return "vpvc", true
	case 1520:
		return "atm-zip-office", true
	case 1521:
		return "ncube-lm", true
	case 1522:
		return "ricardo-lm", true
	case 1523:
		return "cichild-lm", true
	case 1524:
		return "ingreslock", true
	case 1525:
		return "orasrv", true
	case 1526:
		return "pdap-np", true
	case 1527:
		return "tlisrv", true
	case 1528:
		return "norp", true
	case 1529:
		return "coauthor", true
	case 1530:
		return "rap-service", true
	case 1531:
		return "rap-listen", true
	case 1532:
		return "miroconnect", true
	case 1533:
		return "virtual-places", true
	case 1534:
		return "micromuse-lm", true
	case 1535:
		return "ampr-info", true
	case 1536:
		return "ampr-inter", true
	case 1537:
		return "sdsc-lm", true
	case 1538:
		return "3ds-lm", true
	case 1539:
		return "intellistor-lm", true
	case 1540:
		return "rds", true
	case 1541:
		return "rds2", true
	case 1542:
		return "gridgen-elmd", true
	case 1543:
		return "simba-cs", true
	case 1544:
		return "aspeclmd", true
	case 1545:
		return "vistium-share", true
	case 1546:
		return "abbaccuray", true
	case 1547:
		return "laplink", true
	case 1548:
		return "axon-lm", true
	case 1549:
		return "shivahose", true
	case 1550:
		return "3m-image-lm", true
	case 1551:
		return "hecmtl-db", true
	case 1552:
		return "pciarray", true
	case 1553:
		return "sna-cs", true
	case 1554:
		return "caci-lm", true
	case 1555:
		return "livelan", true
	case 1556:
		return "veritas-pbx", true
	case 1557:
		return "arbortext-lm", true
	case 1558:
		return "xingmpeg", true
	case 1559:
		return "web2host", true
	case 1560:
		return "asci-val", true
	case 1561:
		return "facilityview", true
	case 1562:
		return "pconnectmgr", true
	case 1563:
		return "cadabra-lm", true
	case 1564:
		return "pay-per-view", true
	case 1565:
		return "winddlb", true
	case 1566:
		return "corelvideo", true
	case 1567:
		return "jlicelmd", true
	case 1568:
		return "tsspmap", true
	case 1569:
		return "ets", true
	case 1570:
		return "orbixd", true
	case 1571:
		return "rdb-dbs-disp", true
	case 1572:
		return "chip-lm", true
	case 1573:
		return "itscomm-ns", true
	case 1574:
		return "mvel-lm", true
	case 1575:
		return "oraclenames", true
	case 1576:
		return "moldflow-lm", true
	case 1577:
		return "hypercube-lm", true
	case 1578:
		return "jacobus-lm", true
	case 1579:
		return "ioc-sea-lm", true
	case 1580:
		return "tn-tl-r1", true
	case 1581:
		return "mil-2045-47001", true
	case 1582:
		return "msims", true
	case 1583:
		return "simbaexpress", true
	case 1584:
		return "tn-tl-fd2", true
	case 1585:
		return "intv", true
	case 1586:
		return "ibm-abtact", true
	case 1587:
		return "pra-elmd", true
	case 1588:
		return "triquest-lm", true
	case 1589:
		return "vqp", true
	case 1590:
		return "gemini-lm", true
	case 1591:
		return "ncpm-pm", true
	case 1592:
		return "commonspace", true
	case 1593:
		return "mainsoft-lm", true
	case 1594:
		return "sixtrak", true
	case 1595:
		return "radio", true
	case 1596:
		return "radio-sm", true
	case 1597:
		return "orbplus-iiop", true
	case 1598:
		return "picknfs", true
	case 1599:
		return "simbaservices", true
	case 1600:
		return "issd", true
	case 1601:
		return "aas", true
	case 1602:
		return "inspect", true
	case 1603:
		return "picodbc", true
	case 1604:
		return "icabrowser", true
	case 1605:
		return "slp", true
	case 1606:
		return "slm-api", true
	case 1607:
		return "stt", true
	case 1608:
		return "smart-lm", true
	case 1609:
		return "isysg-lm", true
	case 1610:
		return "taurus-wh", true
	case 1611:
		return "ill", true
	case 1612:
		return "netbill-trans", true
	case 1613:
		return "netbill-keyrep", true
	case 1614:
		return "netbill-cred", true
	case 1615:
		return "netbill-auth", true
	case 1616:
		return "netbill-prod", true
	case 1617:
		return "nimrod-agent", true
	case 1618:
		return "skytelnet", true
	case 1619:
		return "xs-openstorage", true
	case 1620:
		return "faxportwinport", true
	case 1621:
		return "softdataphone", true
	case 1622:
		return "ontime", true
	case 1623:
		return "jaleosnd", true
	case 1624:
		return "udp-sr-port", true
	case 1625:
		return "svs-omagent", true
	case 1626:
		return "shockwave", true
	case 1627:
		return "t128-gateway", true
	case 1628:
		return "lontalk-norm", true
	case 1629:
		return "lontalk-urgnt", true
	case 1630:
		return "oraclenet8cman", true
	case 1631:
		return "visitview", true
	case 1632:
		return "pammratc", true
	case 1633:
		return "pammrpc", true
	case 1634:
		return "loaprobe", true
	case 1635:
		return "edb-server1", true
	case 1636:
		return "isdc", true
	case 1637:
		return "islc", true
	case 1638:
		return "ismc", true
	case 1639:
		return "cert-initiator", true
	case 1640:
		return "cert-responder", true
	case 1641:
		return "invision", true
	case 1642:
		return "isis-am", true
	case 1643:
		return "isis-ambc", true
	case 1644:
		return "saiseh", true
	case 1645:
		return "sightline", true
	case 1646:
		return "sa-msg-port", true
	case 1647:
		return "rsap", true
	case 1648:
		return "concurrent-lm", true
	case 1649:
		return "kermit", true
	case 1650:
		return "nkd", true
	case 1651:
		return "shiva-confsrvr", true
	case 1652:
		return "xnmp", true
	case 1653:
		return "alphatech-lm", true
	case 1654:
		return "stargatealerts", true
	case 1655:
		return "dec-mbadmin", true
	case 1656:
		return "dec-mbadmin-h", true
	case 1657:
		return "fujitsu-mmpdc", true
	case 1658:
		return "sixnetudr", true
	case 1659:
		return "sg-lm", true
	case 1660:
		return "skip-mc-gikreq", true
	case 1661:
		return "netview-aix-1", true
	case 1662:
		return "netview-aix-2", true
	case 1663:
		return "netview-aix-3", true
	case 1664:
		return "netview-aix-4", true
	case 1665:
		return "netview-aix-5", true
	case 1666:
		return "netview-aix-6", true
	case 1667:
		return "netview-aix-7", true
	case 1668:
		return "netview-aix-8", true
	case 1669:
		return "netview-aix-9", true
	case 1670:
		return "netview-aix-10", true
	case 1671:
		return "netview-aix-11", true
	case 1672:
		return "netview-aix-12", true
	case 1673:
		return "proshare-mc-1", true
	case 1674:
		return "proshare-mc-2", true
	case 1675:
		return "pdp", true
	case 1676:
		return "netcomm1", true
	case 1677:
		return "groupwise", true
	case 1678:
		return "prolink", true
	case 1679:
		return "darcorp-lm", true
	case 1680:
		return "microcom-sbp", true
	case 1681:
		return "sd-elmd", true
	case 1682:
		return "lanyon-lantern", true
	case 1683:
		return "ncpm-hip", true
	case 1684:
		return "snaresecure", true
	case 1685:
		return "n2nremote", true
	case 1686:
		return "cvmon", true
	case 1687:
		return "nsjtp-ctrl", true
	case 1688:
		return "nsjtp-data", true
	case 1689:
		return "firefox", true
	case 1690:
		return "ng-umds", true
	case 1691:
		return "empire-empuma", true
	case 1692:
		return "sstsys-lm", true
	case 1693:
		return "rrirtr", true
	case 1694:
		return "rrimwm", true
	case 1695:
		return "rrilwm", true
	case 1696:
		return "rrifmm", true
	case 1697:
		return "rrisat", true
	case 1698:
		return "rsvp-encap-1", true
	case 1699:
		return "rsvp-encap-2", true
	case 1700:
		return "mps-raft", true
	case 1701:
		return "l2f", true
	case 1702:
		return "deskshare", true
	case 1703:
		return "hb-engine", true
	case 1704:
		return "bcs-broker", true
	case 1705:
		return "slingshot", true
	case 1706:
		return "jetform", true
	case 1707:
		return "vdmplay", true
	case 1708:
		return "gat-lmd", true
	case 1709:
		return "centra", true
	case 1710:
		return "impera", true
	case 1711:
		return "pptconference", true
	case 1712:
		return "registrar", true
	case 1713:
		return "conferencetalk", true
	case 1714:
		return "sesi-lm", true
	case 1715:
		return "houdini-lm", true
	case 1716:
		return "xmsg", true
	case 1717:
		return "fj-hdnet", true
	case 1718:
		return "h323gatedisc", true
	case 1719:
		return "h323gatestat", true
	case 1720:
		return "h323hostcall", true
	case 1721:
		return "caicci", true
	case 1722:
		return "hks-lm", true
	case 1723:
		return "pptp", true
	case 1724:
		return "csbphonemaster", true
	case 1725:
		return "iden-ralp", true
	case 1726:
		return "iberiagames", true
	case 1727:
		return "winddx", true
	case 1728:
		return "telindus", true
	case 1729:
		return "citynl", true
	case 1730:
		return "roketz", true
	case 1731:
		return "msiccp", true
	case 1732:
		return "proxim", true
	case 1733:
		return "siipat", true
	case 1734:
		return "cambertx-lm", true
	case 1735:
		return "privatechat", true
	case 1736:
		return "street-stream", true
	case 1737:
		return "ultimad", true
	case 1738:
		return "gamegen1", true
	case 1739:
		return "webaccess", true
	case 1740:
		return "encore", true
	case 1741:
		return "cisco-net-mgmt", true
	case 1742:
		return "3Com-nsd", true
	case 1743:
		return "cinegrfx-lm", true
	case 1744:
		return "ncpm-ft", true
	case 1745:
		return "remote-winsock", true
	case 1746:
		return "ftrapid-1", true
	case 1747:
		return "ftrapid-2", true
	case 1748:
		return "oracle-em1", true
	case 1749:
		return "aspen-services", true
	case 1750:
		return "sslp", true
	case 1751:
		return "swiftnet", true
	case 1752:
		return "lofr-lm", true
	case 1753:
		return "predatar-comms", true
	case 1754:
		return "oracle-em2", true
	case 1755:
		return "ms-streaming", true
	case 1756:
		return "capfast-lmd", true
	case 1757:
		return "cnhrp", true
	case 1758:
		return "tftp-mcast", true
	case 1759:
		return "spss-lm", true
	case 1760:
		return "www-ldap-gw", true
	case 1761:
		return "cft-0", true
	case 1762:
		return "cft-1", true
	case 1763:
		return "cft-2", true
	case 1764:
		return "cft-3", true
	case 1765:
		return "cft-4", true
	case 1766:
		return "cft-5", true
	case 1767:
		return "cft-6", true
	case 1768:
		return "cft-7", true
	case 1769:
		return "bmc-net-adm", true
	case 1770:
		return "bmc-net-svc", true
	case 1771:
		return "vaultbase", true
	case 1772:
		return "essweb-gw", true
	case 1773:
		return "kmscontrol", true
	case 1774:
		return "global-dtserv", true
	case 1775:
		return "vdab", true
	case 1776:
		return "femis", true
	case 1777:
		return "powerguardian", true
	case 1778:
		return "prodigy-intrnet", true
	case 1779:
		return "pharmasoft", true
	case 1780:
		return "dpkeyserv", true
	case 1781:
		return "answersoft-lm", true
	case 1782:
		return "hp-hcip", true
	case 1784:
		return "finle-lm", true
	case 1785:
		return "windlm", true
	case 1786:
		return "funk-logger", true
	case 1787:
		return "funk-license", true
	case 1788:
		return "psmond", true
	case 1789:
		return "hello", true
	case 1790:
		return "nmsp", true
	case 1791:
		return "ea1", true
	case 1792:
		return "ibm-dt-2", true
	case 1793:
		return "rsc-robot", true
	case 1794:
		return "cera-bcm", true
	case 1795:
		return "dpi-proxy", true
	case 1796:
		return "vocaltec-admin", true
	case 1797:
		return "uma", true
	case 1798:
		return "etp", true
	case 1799:
		return "netrisk", true
	case 1800:
		return "ansys-lm", true
	case 1801:
		return "msmq", true
	case 1802:
		return "concomp1", true
	case 1803:
		return "hp-hcip-gwy", true
	case 1804:
		return "enl", true
	case 1805:
		return "enl-name", true
	case 1806:
		return "musiconline", true
	case 1807:
		return "fhsp", true
	case 1808:
		return "oracle-vp2", true
	case 1809:
		return "oracle-vp1", true
	case 1810:
		return "jerand-lm", true
	case 1811:
		return "scientia-sdb", true
	case 1812:
		return "radius", true
	case 1813:
		return "radius-acct", true
	case 1814:
		return "tdp-suite", true
	case 1815:
		return "mmpft", true
	case 1816:
		return "harp", true
	case 1817:
		return "rkb-oscs", true
	case 1818:
		return "etftp", true
	case 1819:
		return "plato-lm", true
	case 1820:
		return "mcagent", true
	case 1821:
		return "donnyworld", true
	case 1822:
		return "es-elmd", true
	case 1823:
		return "unisys-lm", true
	case 1824:
		return "metrics-pas", true
	case 1825:
		return "direcpc-video", true
	case 1826:
		return "ardt", true
	case 1827:
		return "asi", true
	case 1828:
		return "itm-mcell-u", true
	case 1829:
		return "optika-emedia", true
	case 1830:
		return "net8-cman", true
	case 1831:
		return "myrtle", true
	case 1832:
		return "tht-treasure", true
	case 1833:
		return "udpradio", true
	case 1834:
		return "ardusuni", true
	case 1835:
		return "ardusmul", true
	case 1836:
		return "ste-smsc", true
	case 1837:
		return "csoft1", true
	case 1838:
		return "talnet", true
	case 1839:
		return "netopia-vo1", true
	case 1840:
		return "netopia-vo2", true
	case 1841:
		return "netopia-vo3", true
	case 1842:
		return "netopia-vo4", true
	case 1843:
		return "netopia-vo5", true
	case 1844:
		return "direcpc-dll", true
	case 1845:
		return "altalink", true
	case 1846:
		return "tunstall-pnc", true
	case 1847:
		return "slp-notify", true
	case 1848:
		return "fjdocdist", true
	case 1849:
		return "alpha-sms", true
	case 1850:
		return "gsi", true
	case 1851:
		return "ctcd", true
	case 1852:
		return "virtual-time", true
	case 1853:
		return "vids-avtp", true
	case 1854:
		return "buddy-draw", true
	case 1855:
		return "fiorano-rtrsvc", true
	case 1856:
		return "fiorano-msgsvc", true
	case 1857:
		return "datacaptor", true
	case 1858:
		return "privateark", true
	case 1859:
		return "gammafetchsvr", true
	case 1860:
		return "sunscalar-svc", true
	case 1861:
		return "lecroy-vicp", true
	case 1862:
		return "mysql-cm-agent", true
	case 1863:
		return "msnp", true
	case 1864:
		return "paradym-31port", true
	case 1865:
		return "entp", true
	case 1866:
		return "swrmi", true
	case 1867:
		return "udrive", true
	case 1868:
		return "viziblebrowser", true
	case 1869:
		return "transact", true
	case 1870:
		return "sunscalar-dns", true
	case 1871:
		return "canocentral0", true
	case 1872:
		return "canocentral1", true
	case 1873:
		return "fjmpjps", true
	case 1874:
		return "fjswapsnp", true
	case 1875:
		return "westell-stats", true
	case 1876:
		return "ewcappsrv", true
	case 1877:
		return "hp-webqosdb", true
	case 1878:
		return "drmsmc", true
	case 1879:
		return "nettgain-nms", true
	case 1880:
		return "vsat-control", true
	case 1881:
		return "ibm-mqseries2", true
	case 1882:
		return "ecsqdmn", true
	case 1883:
		return "mqtt", true
	case 1884:
		return "idmaps", true
	case 1885:
		return "vrtstrapserver", true
	case 1886:
		return "leoip", true
	case 1887:
		return "filex-lport", true
	case 1888:
		return "ncconfig", true
	case 1889:
		return "unify-adapter", true
	case 1890:
		return "wilkenlistener", true
	case 1891:
		return "childkey-notif", true
	case 1892:
		return "childkey-ctrl", true
	case 1893:
		return "elad", true
	case 1894:
		return "o2server-port", true
	case 1896:
		return "b-novative-ls", true
	case 1897:
		return "metaagent", true
	case 1898:
		return "cymtec-port", true
	case 1899:
		return "mc2studios", true
	case 1900:
		return "ssdp", true
	case 1901:
		return "fjicl-tep-a", true
	case 1902:
		return "fjicl-tep-b", true
	case 1903:
		return "linkname", true
	case 1904:
		return "fjicl-tep-c", true
	case 1905:
		return "sugp", true
	case 1906:
		return "tpmd", true
	case 1907:
		return "intrastar", true
	case 1908:
		return "dawn", true
	case 1909:
		return "global-wlink", true
	case 1910:
		return "ultrabac", true
	case 1911:
		return "mtp", true
	case 1912:
		return "rhp-iibp", true
	case 1913:
		return "armadp", true
	case 1914:
		return "elm-momentum", true
	case 1915:
		return "facelink", true
	case 1916:
		return "persona", true
	case 1917:
		return "noagent", true
	case 1918:
		return "can-nds", true
	case 1919:
		return "can-dch", true
	case 1920:
		return "can-ferret", true
	case 1921:
		return "noadmin", true
	case 1922:
		return "tapestry", true
	case 1923:
		return "spice", true
	case 1924:
		return "xiip", true
	case 1925:
		return "discovery-port", true
	case 1926:
		return "egs", true
	case 1927:
		return "videte-cipc", true
	case 1928:
		return "emsd-port", true
	case 1929:
		return "bandwiz-system", true
	case 1930:
		return "driveappserver", true
	case 1931:
		return "amdsched", true
	case 1932:
		return "ctt-broker", true
	case 1933:
		return "xmapi", true
	case 1934:
		return "xaapi", true
	case 1935:
		return "macromedia-fcs", true
	case 1936:
		return "jetcmeserver", true
	case 1937:
		return "jwserver", true
	case 1938:
		return "jwclient", true
	case 1939:
		return "jvserver", true
	case 1940:
		return "jvclient", true
	case 1941:
		return "dic-aida", true
	case 1942:
		return "res", true
	case 1943:
		return "beeyond-media", true
	case 1944:
		return "close-combat", true
	case 1945:
		return "dialogic-elmd", true
	case 1946:
		return "tekpls", true
	case 1947:
		return "sentinelsrm", true
	case 1948:
		return "eye2eye", true
	case 1949:
		return "ismaeasdaqlive", true
	case 1950:
		return "ismaeasdaqtest", true
	case 1951:
		return "bcs-lmserver", true
	case 1952:
		return "mpnjsc", true
	case 1953:
		return "rapidbase", true
	case 1954:
		return "abr-api", true
	case 1955:
		return "abr-secure", true
	case 1956:
		return "vrtl-vmf-ds", true
	case 1957:
		return "unix-status", true
	case 1958:
		return "dxadmind", true
	case 1959:
		return "simp-all", true
	case 1960:
		return "nasmanager", true
	case 1961:
		return "bts-appserver", true
	case 1962:
		return "biap-mp", true
	case 1963:
		return "webmachine", true
	case 1964:
		return "solid-e-engine", true
	case 1965:
		return "tivoli-npm", true
	case 1966:
		return "slush", true
	case 1967:
		return "sns-quote", true
	case 1968:
		return "lipsinc", true
	case 1969:
		return "lipsinc1", true
	case 1970:
		return "netop-rc", true
	case 1971:
		return "netop-school", true
	case 1972:
		return "intersys-cache", true
	case 1973:
		return "dlsrap", true
	case 1974:
		return "drp", true
	case 1975:
		return "tcoflashagent", true
	case 1976:
		return "tcoregagent", true
	case 1977:
		return "tcoaddressbook", true
	case 1978:
		return "unisql", true
	case 1979:
		return "unisql-java", true
	case 1980:
		return "pearldoc-xact", true
	case 1981:
		return "p2pq", true
	case 1982:
		return "estamp", true
	case 1983:
		return "lhtp", true
	case 1984:
		return "bb", true
	case 1985:
		return "hsrp", true
	case 1986:
		return "licensedaemon", true
	case 1987:
		return "tr-rsrb-p1", true
	case 1988:
		return "tr-rsrb-p2", true
	case 1989:
		return "tr-rsrb-p3", true
	case 1990:
		return "stun-p1", true
	case 1991:
		return "stun-p2", true
	case 1992:
		return "stun-p3", true
	case 1993:
		return "snmp-tcp-port", true
	case 1994:
		return "stun-port", true
	case 1995:
		return "perf-port", true
	case 1996:
		return "tr-rsrb-port", true
	case 1997:
		return "gdp-port", true
	case 1998:
		return "x25-svc-port", true
	case 1999:
		return "tcp-id-port", true
	case 2000:
		return "cisco-sccp", true
	case 2001:
		return "dc", true
	case 2002:
		return "globe", true
	case 2003:
		return "brutus", true
	case 2004:
		return "mailbox", true
	case 2005:
		return "berknet", true
	case 2006:
		return "invokator", true
	case 2007:
		return "dectalk", true
	case 2008:
		return "conf", true
	case 2009:
		return "news", true
	case 2010:
		return "search", true
	case 2011:
		return "raid-cc", true
	case 2012:
		return "ttyinfo", true
	case 2013:
		return "raid-am", true
	case 2014:
		return "troff", true
	case 2015:
		return "cypress", true
	case 2016:
		return "bootserver", true
	case 2017:
		return "cypress-stat", true
	case 2018:
		return "terminaldb", true
	case 2019:
		return "whosockami", true
	case 2020:
		return "xinupageserver", true
	case 2021:
		return "servexec", true
	case 2022:
		return "down", true
	case 2023:
		return "xinuexpansion3", true
	case 2024:
		return "xinuexpansion4", true
	case 2025:
		return "ellpack", true
	case 2026:
		return "scrabble", true
	case 2027:
		return "shadowserver", true
	case 2028:
		return "submitserver", true
	case 2029:
		return "hsrpv6", true
	case 2030:
		return "device2", true
	case 2031:
		return "mobrien-chat", true
	case 2032:
		return "blackboard", true
	case 2033:
		return "glogger", true
	case 2034:
		return "scoremgr", true
	case 2035:
		return "imsldoc", true
	case 2036:
		return "e-dpnet", true
	case 2037:
		return "applus", true
	case 2038:
		return "objectmanager", true
	case 2039:
		return "prizma", true
	case 2040:
		return "lam", true
	case 2041:
		return "interbase", true
	case 2042:
		return "isis", true
	case 2043:
		return "isis-bcast", true
	case 2044:
		return "rimsl", true
	case 2045:
		return "cdfunc", true
	case 2046:
		return "sdfunc", true
	case 2047:
		return "dls", true
	case 2048:
		return "dls-monitor", true
	case 2049:
		return "shilp", true
	case 2050:
		return "av-emb-config", true
	case 2051:
		return "epnsdp", true
	case 2052:
		return "clearvisn", true
	case 2053:
		return "lot105-ds-upd", true
	case 2054:
		return "weblogin", true
	case 2055:
		return "iop", true
	case 2056:
		return "omnisky", true
	case 2057:
		return "rich-cp", true
	case 2058:
		return "newwavesearch", true
	case 2059:
		return "bmc-messaging", true
	case 2060:
		return "teleniumdaemon", true
	case 2061:
		return "netmount", true
	case 2062:
		return "icg-swp", true
	case 2063:
		return "icg-bridge", true
	case 2064:
		return "icg-iprelay", true
	case 2065:
		return "dlsrpn", true
	case 2066:
		return "aura", true
	case 2067:
		return "dlswpn", true
	case 2068:
		return "avauthsrvprtcl", true
	case 2069:
		return "event-port", true
	case 2070:
		return "ah-esp-encap", true
	case 2071:
		return "acp-port", true
	case 2072:
		return "msync", true
	case 2073:
		return "gxs-data-port", true
	case 2074:
		return "vrtl-vmf-sa", true
	case 2075:
		return "newlixengine", true
	case 2076:
		return "newlixconfig", true
	case 2077:
		return "tsrmagt", true
	case 2078:
		return "tpcsrvr", true
	case 2079:
		return "idware-router", true
	case 2080:
		return "autodesk-nlm", true
	case 2081:
		return "kme-trap-port", true
	case 2082:
		return "infowave", true
	case 2083:
		return "radsec", true
	case 2084:
		return "sunclustergeo", true
	case 2085:
		return "ada-cip", true
	case 2086:
		return "gnunet", true
	case 2087:
		return "eli", true
	case 2088:
		return "ip-blf", true
	case 2089:
		return "sep", true
	case 2090:
		return "lrp", true
	case 2091:
		return "prp", true
	case 2092:
		return "descent3", true
	case 2093:
		return "nbx-cc", true
	case 2094:
		return "nbx-au", true
	case 2095:
		return "nbx-ser", true
	case 2096:
		return "nbx-dir", true
	case 2097:
		return "jetformpreview", true
	case 2098:
		return "dialog-port", true
	case 2099:
		return "h2250-annex-g", true
	case 2100:
		return "amiganetfs", true
	case 2101:
		return "rtcm-sc104", true
	case 2102:
		return "zephyr-srv", true
	case 2103:
		return "zephyr-clt", true
	case 2104:
		return "zephyr-hm", true
	case 2105:
		return "minipay", true
	case 2106:
		return "mzap", true
	case 2107:
		return "bintec-admin", true
	case 2108:
		return "comcam", true
	case 2109:
		return "ergolight", true
	case 2110:
		return "umsp", true
	case 2111:
		return "dsatp", true
	case 2112:
		return "idonix-metanet", true
	case 2113:
		return "hsl-storm", true
	case 2114:
		return "ariascribe", true
	case 2115:
		return "kdm", true
	case 2116:
		return "ccowcmr", true
	case 2117:
		return "mentaclient", true
	case 2118:
		return "mentaserver", true
	case 2119:
		return "gsigatekeeper", true
	case 2120:
		return "qencp", true
	case 2121:
		return "scientia-ssdb", true
	case 2122:
		return "caupc-remote", true
	case 2123:
		return "gtp-control", true
	case 2124:
		return "elatelink", true
	case 2125:
		return "lockstep", true
	case 2126:
		return "pktcable-cops", true
	case 2127:
		return "index-pc-wb", true
	case 2128:
		return "net-steward", true
	case 2129:
		return "cs-live", true
	case 2130:
		return "xds", true
	case 2131:
		return "avantageb2b", true
	case 2132:
		return "solera-epmap", true
	case 2133:
		return "zymed-zpp", true
	case 2134:
		return "avenue", true
	case 2135:
		return "gris", true
	case 2136:
		return "appworxsrv", true
	case 2137:
		return "connect", true
	case 2138:
		return "unbind-cluster", true
	case 2139:
		return "ias-auth", true
	case 2140:
		return "ias-reg", true
	case 2141:
		return "ias-admind", true
	case 2142:
		return "tdmoip", true
	case 2143:
		return "lv-jc", true
	case 2144:
		return "lv-ffx", true
	case 2145:
		return "lv-pici", true
	case 2146:
		return "lv-not", true
	case 2147:
		return "lv-auth", true
	case 2148:
		return "veritas-ucl", true
	case 2149:
		return "acptsys", true
	case 2150:
		return "dynamic3d", true
	case 2151:
		return "docent", true
	case 2152:
		return "gtp-user", true
	case 2153:
		return "ctlptc", true
	case 2154:
		return "stdptc", true
	case 2155:
		return "brdptc", true
	case 2156:
		return "trp", true
	case 2157:
		return "xnds", true
	case 2158:
		return "touchnetplus", true
	case 2159:
		return "gdbremote", true
	case 2160:
		return "apc-2160", true
	case 2161:
		return "apc-2161", true
	case 2162:
		return "navisphere", true
	case 2163:
		return "navisphere-sec", true
	case 2164:
		return "ddns-v3", true
	case 2165:
		return "x-bone-api", true
	case 2166:
		return "iwserver", true
	case 2167:
		return "raw-serial", true
	case 2168:
		return "easy-soft-mux", true
	case 2169:
		return "brain", true
	case 2170:
		return "eyetv", true
	case 2171:
		return "msfw-storage", true
	case 2172:
		return "msfw-s-storage", true
	case 2173:
		return "msfw-replica", true
	case 2174:
		return "msfw-array", true
	case 2175:
		return "airsync", true
	case 2176:
		return "rapi", true
	case 2177:
		return "qwave", true
	case 2178:
		return "bitspeer", true
	case 2179:
		return "vmrdp", true
	case 2180:
		return "mc-gt-srv", true
	case 2181:
		return "eforward", true
	case 2182:
		return "cgn-stat", true
	case 2183:
		return "cgn-config", true
	case 2184:
		return "nvd", true
	case 2185:
		return "onbase-dds", true
	case 2186:
		return "gtaua", true
	case 2187:
		return "ssmc", true
	case 2188:
		return "radware-rpm", true
	case 2189:
		return "radware-rpm-s", true
	case 2190:
		return "tivoconnect", true
	case 2191:
		return "tvbus", true
	case 2192:
		return "asdis", true
	case 2193:
		return "drwcs", true
	case 2197:
		return "mnp-exchange", true
	case 2198:
		return "onehome-remote", true
	case 2199:
		return "onehome-help", true
	case 2201:
		return "ats", true
	case 2202:
		return "imtc-map", true
	case 2203:
		return "b2-runtime", true
	case 2204:
		return "b2-license", true
	case 2205:
		return "jps", true
	case 2206:
		return "hpocbus", true
	case 2207:
		return "hpssd", true
	case 2208:
		return "hpiod", true
	case 2209:
		return "rimf-ps", true
	case 2210:
		return "noaaport", true
	case 2211:
		return "emwin", true
	case 2212:
		return "leecoposserver", true
	case 2213:
		return "kali", true
	case 2214:
		return "rpi", true
	case 2215:
		return "ipcore", true
	case 2216:
		return "vtu-comms", true
	case 2217:
		return "gotodevice", true
	case 2218:
		return "bounzza", true
	case 2219:
		return "netiq-ncap", true
	case 2220:
		return "netiq", true
	case 2221:
		return "ethernet-ip-s", true
	case 2222:
		return "EtherNet-IP-1", true
	case 2223:
		return "rockwell-csp2", true
	case 2224:
		return "efi-mg", true
	case 2225:
		return "rcip-itu", true
	case 2226:
		return "di-drm", true
	case 2227:
		return "di-msg", true
	case 2228:
		return "ehome-ms", true
	case 2229:
		return "datalens", true
	case 2230:
		return "queueadm", true
	case 2231:
		return "wimaxasncp", true
	case 2232:
		return "ivs-video", true
	case 2233:
		return "infocrypt", true
	case 2234:
		return "directplay", true
	case 2235:
		return "sercomm-wlink", true
	case 2236:
		return "nani", true
	case 2237:
		return "optech-port1-lm", true
	case 2238:
		return "aviva-sna", true
	case 2239:
		return "imagequery", true
	case 2240:
		return "recipe", true
	case 2241:
		return "ivsd", true
	case 2242:
		return "foliocorp", true
	case 2243:
		return "magicom", true
	case 2244:
		return "nmsserver", true
	case 2245:
		return "hao", true
	case 2246:
		return "pc-mta-addrmap", true
	case 2247:
		return "antidotemgrsvr", true
	case 2248:
		return "ums", true
	case 2249:
		return "rfmp", true
	case 2250:
		return "remote-collab", true
	case 2251:
		return "dif-port", true
	case 2252:
		return "njenet-ssl", true
	case 2253:
		return "dtv-chan-req", true
	case 2254:
		return "seispoc", true
	case 2255:
		return "vrtp", true
	case 2256:
		return "pcc-mfp", true
	case 2257:
		return "simple-tx-rx", true
	case 2258:
		return "rcts", true
	case 2259:
		return "bid-serv", true
	case 2260:
		return "apc-2260", true
	case 2261:
		return "comotionmaster", true
	case 2262:
		return "comotionback", true
	case 2263:
		return "ecwcfg", true
	case 2264:
		return "apx500api-1", true
	case 2265:
		return "apx500api-2", true
	case 2266:
		return "mfserver", true
	case 2267:
		return "ontobroker", true
	case 2268:
		return "amt", true
	case 2269:
		return "mikey", true
	case 2270:
		return "starschool", true
	case 2271:
		return "mmcals", true
	case 2272:
		return "mmcal", true
	case 2273:
		return "mysql-im", true
	case 2274:
		return "pcttunnell", true
	case 2275:
		return "ibridge-data", true
	case 2276:
		return "ibridge-mgmt", true
	case 2277:
		return "bluectrlproxy", true
	case 2278:
		return "s3db", true
	case 2279:
		return "xmquery", true
	case 2280:
		return "lnvpoller", true
	case 2281:
		return "lnvconsole", true
	case 2282:
		return "lnvalarm", true
	case 2283:
		return "lnvstatus", true
	case 2284:
		return "lnvmaps", true
	case 2285:
		return "lnvmailmon", true
	case 2286:
		return "nas-metering", true
	case 2287:
		return "dna", true
	case 2288:
		return "netml", true
	case 2289:
		return "dict-lookup", true
	case 2290:
		return "sonus-logging", true
	case 2291:
		return "eapsp", true
	case 2292:
		return "mib-streaming", true
	case 2293:
		return "npdbgmngr", true
	case 2294:
		return "konshus-lm", true
	case 2295:
		return "advant-lm", true
	case 2296:
		return "theta-lm", true
	case 2297:
		return "d2k-datamover1", true
	case 2298:
		return "d2k-datamover2", true
	case 2299:
		return "pc-telecommute", true
	case 2300:
		return "cvmmon", true
	case 2301:
		return "cpq-wbem", true
	case 2302:
		return "binderysupport", true
	case 2303:
		return "proxy-gateway", true
	case 2304:
		return "attachmate-uts", true
	case 2305:
		return "mt-scaleserver", true
	case 2306:
		return "tappi-boxnet", true
	case 2307:
		return "pehelp", true
	case 2308:
		return "sdhelp", true
	case 2309:
		return "sdserver", true
	case 2310:
		return "sdclient", true
	case 2311:
		return "messageservice", true
	case 2312:
		return "wanscaler", true
	case 2313:
		return "iapp", true
	case 2314:
		return "cr-websystems", true
	case 2315:
		return "precise-sft", true
	case 2316:
		return "sent-lm", true
	case 2317:
		return "attachmate-g32", true
	case 2318:
		return "cadencecontrol", true
	case 2319:
		return "infolibria", true
	case 2320:
		return "siebel-ns", true
	case 2321:
		return "rdlap", true
	case 2322:
		return "ofsd", true
	case 2323:
		return "3d-nfsd", true
	case 2324:
		return "cosmocall", true
	case 2325:
		return "ansysli", true
	case 2326:
		return "idcp", true
	case 2327:
		return "xingcsm", true
	case 2328:
		return "netrix-sftm", true
	case 2329:
		return "nvd", true
	case 2330:
		return "tscchat", true
	case 2331:
		return "agentview", true
	case 2332:
		return "rcc-host", true
	case 2333:
		return "snapp", true
	case 2334:
		return "ace-client", true
	case 2335:
		return "ace-proxy", true
	case 2336:
		return "appleugcontrol", true
	case 2337:
		return "ideesrv", true
	case 2338:
		return "norton-lambert", true
	case 2339:
		return "3com-webview", true
	case 2340:
		return "wrs-registry", true
	case 2341:
		return "xiostatus", true
	case 2342:
		return "manage-exec", true
	case 2343:
		return "nati-logos", true
	case 2344:
		return "fcmsys", true
	case 2345:
		return "dbm", true
	case 2346:
		return "redstorm-join", true
	case 2347:
		return "redstorm-find", true
	case 2348:
		return "redstorm-info", true
	case 2349:
		return "redstorm-diag", true
	case 2350:
		return "psbserver", true
	case 2351:
		return "psrserver", true
	case 2352:
		return "pslserver", true
	case 2353:
		return "pspserver", true
	case 2354:
		return "psprserver", true
	case 2355:
		return "psdbserver", true
	case 2356:
		return "gxtelmd", true
	case 2357:
		return "unihub-server", true
	case 2358:
		return "futrix", true
	case 2359:
		return "flukeserver", true
	case 2360:
		return "nexstorindltd", true
	case 2361:
		return "tl1", true
	case 2362:
		return "digiman", true
	case 2363:
		return "mediacntrlnfsd", true
	case 2364:
		return "oi-2000", true
	case 2365:
		return "dbref", true
	case 2366:
		return "qip-login", true
	case 2367:
		return "service-ctrl", true
	case 2368:
		return "opentable", true
	case 2369:
		return "bif-p2p", true
	case 2370:
		return "l3-hbmon", true
	case 2371:
		return "rda", true
	case 2372:
		return "lanmessenger", true
	case 2373:
		return "remographlm", true
	case 2374:
		return "hydra", true
	case 2375:
		return "docker", true
	case 2376:
		return "docker-s", true
	case 2377:
		return "swarm", true
	case 2379:
		return "etcd-client", true
	case 2380:
		return "etcd-server", true
	case 2381:
		return "compaq-https", true
	case 2382:
		return "ms-olap3", true
	case 2383:
		return "ms-olap4", true
	case 2384:
		return "sd-request", true
	case 2385:
		return "sd-data", true
	case 2386:
		return "virtualtape", true
	case 2387:
		return "vsamredirector", true
	case 2388:
		return "mynahautostart", true
	case 2389:
		return "ovsessionmgr", true
	case 2390:
		return "rsmtp", true
	case 2391:
		return "3com-net-mgmt", true
	case 2392:
		return "tacticalauth", true
	case 2393:
		return "ms-olap1", true
	case 2394:
		return "ms-olap2", true
	case 2395:
		return "lan900-remote", true
	case 2396:
		return "wusage", true
	case 2397:
		return "ncl", true
	case 2398:
		return "orbiter", true
	case 2399:
		return "fmpro-fdal", true
	case 2400:
		return "opequus-server", true
	case 2401:
		return "cvspserver", true
	case 2402:
		return "taskmaster2000", true
	case 2403:
		return "taskmaster2000", true
	case 2404:
		return "iec-104", true
	case 2405:
		return "trc-netpoll", true
	case 2406:
		return "jediserver", true
	case 2407:
		return "orion", true
	case 2408:
		return "railgun-webaccl", true
	case 2409:
		return "sns-protocol", true
	case 2410:
		return "vrts-registry", true
	case 2411:
		return "netwave-ap-mgmt", true
	case 2412:
		return "cdn", true
	case 2413:
		return "orion-rmi-reg", true
	case 2414:
		return "beeyond", true
	case 2415:
		return "codima-rtp", true
	case 2416:
		return "rmtserver", true
	case 2417:
		return "composit-server", true
	case 2418:
		return "cas", true
	case 2419:
		return "attachmate-s2s", true
	case 2420:
		return "dslremote-mgmt", true
	case 2421:
		return "g-talk", true
	case 2422:
		return "crmsbits", true
	case 2423:
		return "rnrp", true
	case 2424:
		return "kofax-svr", true
	case 2425:
		return "fjitsuappmgr", true
	case 2426:
		return "vcmp", true
	case 2427:
		return "mgcp-gateway", true
	case 2428:
		return "ott", true
	case 2429:
		return "ft-role", true
	case 2430:
		return "venus", true
	case 2431:
		return "venus-se", true
	case 2432:
		return "codasrv", true
	case 2433:
		return "codasrv-se", true
	case 2434:
		return "pxc-epmap", true
	case 2435:
		return "optilogic", true
	case 2436:
		return "topx", true
	case 2437:
		return "unicontrol", true
	case 2438:
		return "msp", true
	case 2439:
		return "sybasedbsynch", true
	case 2440:
		return "spearway", true
	case 2441:
		return "pvsw-inet", true
	case 2442:
		return "netangel", true
	case 2443:
		return "powerclientcsf", true
	case 2444:
		return "btpp2sectrans", true
	case 2445:
		return "dtn1", true
	case 2446:
		return "bues-service", true
	case 2447:
		return "ovwdb", true
	case 2448:
		return "hpppssvr", true
	case 2449:
		return "ratl", true
	case 2450:
		return "netadmin", true
	case 2451:
		return "netchat", true
	case 2452:
		return "snifferclient", true
	case 2453:
		return "madge-ltd", true
	case 2454:
		return "indx-dds", true
	case 2455:
		return "wago-io-system", true
	case 2456:
		return "altav-remmgt", true
	case 2457:
		return "rapido-ip", true
	case 2458:
		return "griffin", true
	case 2459:
		return "xrpl", true
	case 2460:
		return "ms-theater", true
	case 2461:
		return "qadmifoper", true
	case 2462:
		return "qadmifevent", true
	case 2463:
		return "lsi-raid-mgmt", true
	case 2464:
		return "direcpc-si", true
	case 2465:
		return "lbm", true
	case 2466:
		return "lbf", true
	case 2467:
		return "high-criteria", true
	case 2468:
		return "qip-msgd", true
	case 2469:
		return "mti-tcs-comm", true
	case 2470:
		return "taskman-port", true
	case 2471:
		return "seaodbc", true
	case 2472:
		return "c3", true
	case 2473:
		return "aker-cdp", true
	case 2474:
		return "vitalanalysis", true
	case 2475:
		return "ace-server", true
	case 2476:
		return "ace-svr-prop", true
	case 2477:
		return "ssm-cvs", true
	case 2478:
		return "ssm-cssps", true
	case 2479:
		return "ssm-els", true
	case 2480:
		return "powerexchange", true
	case 2481:
		return "giop", true
	case 2482:
		return "giop-ssl", true
	case 2483:
		return "ttc", true
	case 2484:
		return "ttc-ssl", true
	case 2485:
		return "netobjects1", true
	case 2486:
		return "netobjects2", true
	case 2487:
		return "pns", true
	case 2488:
		return "moy-corp", true
	case 2489:
		return "tsilb", true
	case 2490:
		return "qip-qdhcp", true
	case 2491:
		return "conclave-cpp", true
	case 2492:
		return "groove", true
	case 2493:
		return "talarian-mqs", true
	case 2494:
		return "bmc-ar", true
	case 2495:
		return "fast-rem-serv", true
	case 2496:
		return "dirgis", true
	case 2497:
		return "quaddb", true
	case 2498:
		return "odn-castraq", true
	case 2499:
		return "unicontrol", true
	case 2500:
		return "rtsserv", true
	case 2501:
		return "rtsclient", true
	case 2502:
		return "kentrox-prot", true
	case 2503:
		return "nms-dpnss", true
	case 2504:
		return "wlbs", true
	case 2505:
		return "ppcontrol", true
	case 2506:
		return "jbroker", true
	case 2507:
		return "spock", true
	case 2508:
		return "jdatastore", true
	case 2509:
		return "fjmpss", true
	case 2510:
		return "fjappmgrbulk", true
	case 2511:
		return "metastorm", true
	case 2512:
		return "citrixima", true
	case 2513:
		return "citrixadmin", true
	case 2514:
		return "facsys-ntp", true
	case 2515:
		return "facsys-router", true
	case 2516:
		return "maincontrol", true
	case 2517:
		return "call-sig-trans", true
	case 2518:
		return "willy", true
	case 2519:
		return "globmsgsvc", true
	case 2520:
		return "pvsw", true
	case 2521:
		return "adaptecmgr", true
	case 2522:
		return "windb", true
	case 2523:
		return "qke-llc-v3", true
	case 2524:
		return "optiwave-lm", true
	case 2525:
		return "ms-v-worlds", true
	case 2526:
		return "ema-sent-lm", true
	case 2527:
		return "iqserver", true
	case 2528:
		return "ncr-ccl", true
	case 2529:
		return "utsftp", true
	case 2530:
		return "vrcommerce", true
	case 2531:
		return "ito-e-gui", true
	case 2532:
		return "ovtopmd", true
	case 2533:
		return "snifferserver", true
	case 2534:
		return "combox-web-acc", true
	case 2535:
		return "madcap", true
	case 2536:
		return "btpp2audctr1", true
	case 2537:
		return "upgrade", true
	case 2538:
		return "vnwk-prapi", true
	case 2539:
		return "vsiadmin", true
	case 2540:
		return "lonworks", true
	case 2541:
		return "lonworks2", true
	case 2542:
		return "udrawgraph", true
	case 2543:
		return "reftek", true
	case 2544:
		return "novell-zen", true
	case 2545:
		return "sis-emt", true
	case 2546:
		return "vytalvaultbrtp", true
	case 2547:
		return "vytalvaultvsmp", true
	case 2548:
		return "vytalvaultpipe", true
	case 2549:
		return "ipass", true
	case 2550:
		return "ads", true
	case 2551:
		return "isg-uda-server", true
	case 2552:
		return "call-logging", true
	case 2553:
		return "efidiningport", true
	case 2554:
		return "vcnet-link-v10", true
	case 2555:
		return "compaq-wcp", true
	case 2556:
		return "nicetec-nmsvc", true
	case 2557:
		return "nicetec-mgmt", true
	case 2558:
		return "pclemultimedia", true
	case 2559:
		return "lstp", true
	case 2560:
		return "labrat", true
	case 2561:
		return "mosaixcc", true
	case 2562:
		return "delibo", true
	case 2563:
		return "cti-redwood", true
	case 2564:
		return "hp-3000-telnet", true
	case 2565:
		return "coord-svr", true
	case 2566:
		return "pcs-pcw", true
	case 2567:
		return "clp", true
	case 2568:
		return "spamtrap", true
	case 2569:
		return "sonuscallsig", true
	case 2570:
		return "hs-port", true
	case 2571:
		return "cecsvc", true
	case 2572:
		return "ibp", true
	case 2573:
		return "trustestablish", true
	case 2574:
		return "blockade-bpsp", true
	case 2575:
		return "hl7", true
	case 2576:
		return "tclprodebugger", true
	case 2577:
		return "scipticslsrvr", true
	case 2578:
		return "rvs-isdn-dcp", true
	case 2579:
		return "mpfoncl", true
	case 2580:
		return "tributary", true
	case 2581:
		return "argis-te", true
	case 2582:
		return "argis-ds", true
	case 2583:
		return "mon", true
	case 2584:
		return "cyaserv", true
	case 2585:
		return "netx-server", true
	case 2586:
		return "netx-agent", true
	case 2587:
		return "masc", true
	case 2588:
		return "privilege", true
	case 2589:
		return "quartus-tcl", true
	case 2590:
		return "idotdist", true
	case 2591:
		return "maytagshuffle", true
	case 2592:
		return "netrek", true
	case 2593:
		return "mns-mail", true
	case 2594:
		return "dts", true
	case 2595:
		return "worldfusion1", true
	case 2596:
		return "worldfusion2", true
	case 2597:
		return "homesteadglory", true
	case 2598:
		return "citriximaclient", true
	case 2599:
		return "snapd", true
	case 2600:
		return "hpstgmgr", true
	case 2601:
		return "discp-client", true
	case 2602:
		return "discp-server", true
	case 2603:
		return "servicemeter", true
	case 2604:
		return "nsc-ccs", true
	case 2605:
		return "nsc-posa", true
	case 2606:
		return "netmon", true
	case 2607:
		return "connection", true
	case 2608:
		return "wag-service", true
	case 2609:
		return "system-monitor", true
	case 2610:
		return "versa-tek", true
	case 2611:
		return "lionhead", true
	case 2612:
		return "qpasa-agent", true
	case 2613:
		return "smntubootstrap", true
	case 2614:
		return "neveroffline", true
	case 2615:
		return "firepower", true
	case 2616:
		return "appswitch-emp", true
	case 2617:
		return "cmadmin", true
	case 2618:
		return "priority-e-com", true
	case 2619:
		return "bruce", true
	case 2620:
		return "lpsrecommender", true
	case 2621:
		return "miles-apart", true
	case 2622:
		return "metricadbc", true
	case 2623:
		return "lmdp", true
	case 2624:
		return "aria", true
	case 2625:
		return "blwnkl-port", true
	case 2626:
		return "gbjd816", true
	case 2627:
		return "moshebeeri", true
	case 2628:
		return "dict", true
	case 2629:
		return "sitaraserver", true
	case 2630:
		return "sitaramgmt", true
	case 2631:
		return "sitaradir", true
	case 2632:
		return "irdg-post", true
	case 2633:
		return "interintelli", true
	case 2634:
		return "pk-electronics", true
	case 2635:
		return "backburner", true
	case 2636:
		return "solve", true
	case 2637:
		return "imdocsvc", true
	case 2638:
		return "sybaseanywhere", true
	case 2639:
		return "aminet", true
	case 2640:
		return "ami-control", true
	case 2641:
		return "hdl-srv", true
	case 2642:
		return "tragic", true
	case 2643:
		return "gte-samp", true
	case 2644:
		return "travsoft-ipx-t", true
	case 2645:
		return "novell-ipx-cmd", true
	case 2646:
		return "and-lm", true
	case 2647:
		return "syncserver", true
	case 2648:
		return "upsnotifyprot", true
	case 2649:
		return "vpsipport", true
	case 2650:
		return "eristwoguns", true
	case 2651:
		return "ebinsite", true
	case 2652:
		return "interpathpanel", true
	case 2653:
		return "sonus", true
	case 2654:
		return "corel-vncadmin", true
	case 2655:
		return "unglue", true
	case 2656:
		return "kana", true
	case 2657:
		return "sns-dispatcher", true
	case 2658:
		return "sns-admin", true
	case 2659:
		return "sns-query", true
	case 2660:
		return "gcmonitor", true
	case 2661:
		return "olhost", true
	case 2662:
		return "bintec-capi", true
	case 2663:
		return "bintec-tapi", true
	case 2664:
		return "patrol-mq-gm", true
	case 2665:
		return "patrol-mq-nm", true
	case 2666:
		return "extensis", true
	case 2667:
		return "alarm-clock-s", true
	case 2668:
		return "alarm-clock-c", true
	case 2669:
		return "toad", true
	case 2670:
		return "tve-announce", true
	case 2671:
		return "newlixreg", true
	case 2672:
		return "nhserver", true
	case 2673:
		return "firstcall42", true
	case 2674:
		return "ewnn", true
	case 2675:
		return "ttc-etap", true
	case 2676:
		return "simslink", true
	case 2677:
		return "gadgetgate1way", true
	case 2678:
		return "gadgetgate2way", true
	case 2679:
		return "syncserverssl", true
	case 2680:
		return "pxc-sapxom", true
	case 2681:
		return "mpnjsomb", true
	case 2683:
		return "ncdloadbalance", true
	case 2684:
		return "mpnjsosv", true
	case 2685:
		return "mpnjsocl", true
	case 2686:
		return "mpnjsomg", true
	case 2687:
		return "pq-lic-mgmt", true
	case 2688:
		return "md-cg-http", true
	case 2689:
		return "fastlynx", true
	case 2690:
		return "hp-nnm-data", true
	case 2691:
		return "itinternet", true
	case 2692:
		return "admins-lms", true
	case 2694:
		return "pwrsevent", true
	case 2695:
		return "vspread", true
	case 2696:
		return "unifyadmin", true
	case 2697:
		return "oce-snmp-trap", true
	case 2698:
		return "mck-ivpip", true
	case 2699:
		return "csoft-plusclnt", true
	case 2700:
		return "tqdata", true
	case 2701:
		return "sms-rcinfo", true
	case 2702:
		return "sms-xfer", true
	case 2703:
		return "sms-chat", true
	case 2704:
		return "sms-remctrl", true
	case 2705:
		return "sds-admin", true
	case 2706:
		return "ncdmirroring", true
	case 2707:
		return "emcsymapiport", true
	case 2708:
		return "banyan-net", true
	case 2709:
		return "supermon", true
	case 2710:
		return "sso-service", true
	case 2711:
		return "sso-control", true
	case 2712:
		return "aocp", true
	case 2713:
		return "raventbs", true
	case 2714:
		return "raventdm", true
	case 2715:
		return "hpstgmgr2", true
	case 2716:
		return "inova-ip-disco", true
	case 2717:
		return "pn-requester", true
	case 2718:
		return "pn-requester2", true
	case 2719:
		return "scan-change", true
	case 2720:
		return "wkars", true
	case 2721:
		return "smart-diagnose", true
	case 2722:
		return "proactivesrvr", true
	case 2723:
		return "watchdog-nt", true
	case 2724:
		return "qotps", true
	case 2725:
		return "msolap-ptp2", true
	case 2726:
		return "tams", true
	case 2727:
		return "mgcp-callagent", true
	case 2728:
		return "sqdr", true
	case 2729:
		return "tcim-control", true
	case 2730:
		return "nec-raidplus", true
	case 2731:
		return "fyre-messanger", true
	case 2732:
		return "g5m", true
	case 2733:
		return "signet-ctf", true
	case 2734:
		return "ccs-software", true
	case 2735:
		return "netiq-mc", true
	case 2736:
		return "radwiz-nms-srv", true
	case 2737:
		return "srp-feedback", true
	case 2738:
		return "ndl-tcp-ois-gw", true
	case 2739:
		return "tn-timing", true
	case 2740:
		return "alarm", true
	case 2741:
		return "tsb", true
	case 2742:
		return "tsb2", true
	case 2743:
		return "murx", true
	case 2744:
		return "honyaku", true
	case 2745:
		return "urbisnet", true
	case 2746:
		return "cpudpencap", true
	case 2747:
		return "fjippol-swrly", true
	case 2748:
		return "fjippol-polsvr", true
	case 2749:
		return "fjippol-cnsl", true
	case 2750:
		return "fjippol-port1", true
	case 2751:
		return "fjippol-port2", true
	case 2752:
		return "rsisysaccess", true
	case 2753:
		return "de-spot", true
	case 2754:
		return "apollo-cc", true
	case 2755:
		return "expresspay", true
	case 2756:
		return "simplement-tie", true
	case 2757:
		return "cnrp", true
	case 2758:
		return "apollo-status", true
	case 2759:
		return "apollo-gms", true
	case 2760:
		return "sabams", true
	case 2761:
		return "dicom-iscl", true
	case 2762:
		return "dicom-tls", true
	case 2763:
		return "desktop-dna", true
	case 2764:
		return "data-insurance", true
	case 2765:
		return "qip-audup", true
	case 2766:
		return "compaq-scp", true
	case 2767:
		return "uadtc", true
	case 2768:
		return "uacs", true
	case 2769:
		return "exce", true
	case 2770:
		return "veronica", true
	case 2771:
		return "vergencecm", true
	case 2772:
		return "auris", true
	case 2773:
		return "rbakcup1", true
	case 2774:
		return "rbakcup2", true
	case 2775:
		return "smpp", true
	case 2776:
		return "ridgeway1", true
	case 2777:
		return "ridgeway2", true
	case 2778:
		return "gwen-sonya", true
	case 2779:
		return "lbc-sync", true
	case 2780:
		return "lbc-control", true
	case 2781:
		return "whosells", true
	case 2782:
		return "everydayrc", true
	case 2783:
		return "aises", true
	case 2784:
		return "www-dev", true
	case 2785:
		return "aic-np", true
	case 2786:
		return "aic-oncrpc", true
	case 2787:
		return "piccolo", true
	case 2788:
		return "fryeserv", true
	case 2789:
		return "media-agent", true
	case 2790:
		return "plgproxy", true
	case 2791:
		return "mtport-regist", true
	case 2792:
		return "f5-globalsite", true
	case 2793:
		return "initlsmsad", true
	case 2795:
		return "livestats", true
	case 2796:
		return "ac-tech", true
	case 2797:
		return "esp-encap", true
	case 2798:
		return "tmesis-upshot", true
	case 2799:
		return "icon-discover", true
	case 2800:
		return "acc-raid", true
	case 2801:
		return "igcp", true
	case 2802:
		return "veritas-tcp1", true
	case 2803:
		return "btprjctrl", true
	case 2804:
		return "dvr-esm", true
	case 2805:
		return "wta-wsp-s", true
	case 2806:
		return "cspuni", true
	case 2807:
		return "cspmulti", true
	case 2808:
		return "j-lan-p", true
	case 2809:
		return "corbaloc", true
	case 2810:
		return "netsteward", true
	case 2811:
		return "gsiftp", true
	case 2812:
		return "atmtcp", true
	case 2813:
		return "llm-pass", true
	case 2814:
		return "llm-csv", true
	case 2815:
		return "lbc-measure", true
	case 2816:
		return "lbc-watchdog", true
	case 2817:
		return "nmsigport", true
	case 2818:
		return "rmlnk", true
	case 2819:
		return "fc-faultnotify", true
	case 2820:
		return "univision", true
	case 2821:
		return "vrts-at-port", true
	case 2822:
		return "ka0wuc", true
	case 2823:
		return "cqg-netlan", true
	case 2824:
		return "cqg-netlan-1", true
	case 2826:
		return "slc-systemlog", true
	case 2827:
		return "slc-ctrlrloops", true
	case 2828:
		return "itm-lm", true
	case 2829:
		return "silkp1", true
	case 2830:
		return "silkp2", true
	case 2831:
		return "silkp3", true
	case 2832:
		return "silkp4", true
	case 2833:
		return "glishd", true
	case 2834:
		return "evtp", true
	case 2835:
		return "evtp-data", true
	case 2836:
		return "catalyst", true
	case 2837:
		return "repliweb", true
	case 2838:
		return "starbot", true
	case 2839:
		return "nmsigport", true
	case 2840:
		return "l3-exprt", true
	case 2841:
		return "l3-ranger", true
	case 2842:
		return "l3-hawk", true
	case 2843:
		return "pdnet", true
	case 2844:
		return "bpcp-poll", true
	case 2845:
		return "bpcp-trap", true
	case 2846:
		return "aimpp-hello", true
	case 2847:
		return "aimpp-port-req", true
	case 2848:
		return "amt-blc-port", true
	case 2849:
		return "fxp", true
	case 2850:
		return "metaconsole", true
	case 2851:
		return "webemshttp", true
	case 2852:
		return "bears-01", true
	case 2853:
		return "ispipes", true
	case 2854:
		return "infomover", true
	case 2855:
		return "msrp", true
	case 2856:
		return "cesdinv", true
	case 2857:
		return "simctlp", true
	case 2858:
		return "ecnp", true
	case 2859:
		return "activememory", true
	case 2860:
		return "dialpad-voice1", true
	case 2861:
		return "dialpad-voice2", true
	case 2862:
		return "ttg-protocol", true
	case 2863:
		return "sonardata", true
	case 2864:
		return "astronova-main", true
	case 2865:
		return "pit-vpn", true
	case 2866:
		return "iwlistener", true
	case 2867:
		return "esps-portal", true
	case 2868:
		return "npep-messaging", true
	case 2869:
		return "icslap", true
	case 2870:
		return "daishi", true
	case 2871:
		return "msi-selectplay", true
	case 2872:
		return "radix", true
	case 2873:
		return "psrt", true
	case 2874:
		return "dxmessagebase1", true
	case 2875:
		return "dxmessagebase2", true
	case 2876:
		return "sps-tunnel", true
	case 2877:
		return "bluelance", true
	case 2878:
		return "aap", true
	case 2879:
		return "ucentric-ds", true
	case 2880:
		return "synapse", true
	case 2881:
		return "ndsp", true
	case 2882:
		return "ndtp", true
	case 2883:
		return "ndnp", true
	case 2884:
		return "flashmsg", true
	case 2885:
		return "topflow", true
	case 2886:
		return "responselogic", true
	case 2887:
		return "aironetddp", true
	case 2888:
		return "spcsdlobby", true
	case 2889:
		return "rsom", true
	case 2890:
		return "cspclmulti", true
	case 2891:
		return "cinegrfx-elmd", true
	case 2892:
		return "snifferdata", true
	case 2893:
		return "vseconnector", true
	case 2894:
		return "abacus-remote", true
	case 2895:
		return "natuslink", true
	case 2896:
		return "ecovisiong6-1", true
	case 2897:
		return "citrix-rtmp", true
	case 2898:
		return "appliance-cfg", true
	case 2899:
		return "powergemplus", true
	case 2900:
		return "quicksuite", true
	case 2901:
		return "allstorcns", true
	case 2902:
		return "netaspi", true
	case 2903:
		return "suitcase", true
	case 2904:
		return "m2ua", true
	case 2905:
		return "m3ua", true
	case 2906:
		return "caller9", true
	case 2907:
		return "webmethods-b2b", true
	case 2908:
		return "mao", true
	case 2909:
		return "funk-dialout", true
	case 2910:
		return "tdaccess", true
	case 2911:
		return "blockade", true
	case 2912:
		return "epicon", true
	case 2913:
		return "boosterware", true
	case 2914:
		return "gamelobby", true
	case 2915:
		return "tksocket", true
	case 2916:
		return "elvin-server", true
	case 2917:
		return "elvin-client", true
	case 2918:
		return "kastenchasepad", true
	case 2919:
		return "roboer", true
	case 2920:
		return "roboeda", true
	case 2921:
		return "cesdcdman", true
	case 2922:
		return "cesdcdtrn", true
	case 2923:
		return "wta-wsp-wtp-s", true
	case 2924:
		return "precise-vip", true
	case 2926:
		return "mobile-file-dl", true
	case 2927:
		return "unimobilectrl", true
	case 2928:
		return "redstone-cpss", true
	case 2929:
		return "amx-webadmin", true
	case 2930:
		return "amx-weblinx", true
	case 2931:
		return "circle-x", true
	case 2932:
		return "incp", true
	case 2933:
		return "4-tieropmgw", true
	case 2934:
		return "4-tieropmcli", true
	case 2935:
		return "qtp", true
	case 2936:
		return "otpatch", true
	case 2937:
		return "pnaconsult-lm", true
	case 2938:
		return "sm-pas-1", true
	case 2939:
		return "sm-pas-2", true
	case 2940:
		return "sm-pas-3", true
	case 2941:
		return "sm-pas-4", true
	case 2942:
		return "sm-pas-5", true
	case 2943:
		return "ttnrepository", true
	case 2944:
		return "megaco-h248", true
	case 2945:
		return "h248-binary", true
	case 2946:
		return "fjsvmpor", true
	case 2947:
		return "gpsd", true
	case 2948:
		return "wap-push", true
	case 2949:
		return "wap-pushsecure", true
	case 2950:
		return "esip", true
	case 2951:
		return "ottp", true
	case 2952:
		return "mpfwsas", true
	case 2953:
		return "ovalarmsrv", true
	case 2954:
		return "ovalarmsrv-cmd", true
	case 2955:
		return "csnotify", true
	case 2956:
		return "ovrimosdbman", true
	case 2957:
		return "jmact5", true
	case 2958:
		return "jmact6", true
	case 2959:
		return "rmopagt", true
	case 2960:
		return "dfoxserver", true
	case 2961:
		return "boldsoft-lm", true
	case 2962:
		return "iph-policy-cli", true
	case 2963:
		return "iph-policy-adm", true
	case 2964:
		return "bullant-srap", true
	case 2965:
		return "bullant-rap", true
	case 2966:
		return "idp-infotrieve", true
	case 2967:
		return "ssc-agent", true
	case 2968:
		return "enpp", true
	case 2969:
		return "essp", true
	case 2970:
		return "index-net", true
	case 2971:
		return "netclip", true
	case 2972:
		return "pmsm-webrctl", true
	case 2973:
		return "svnetworks", true
	case 2974:
		return "signal", true
	case 2975:
		return "fjmpcm", true
	case 2976:
		return "cns-srv-port", true
	case 2977:
		return "ttc-etap-ns", true
	case 2978:
		return "ttc-etap-ds", true
	case 2979:
		return "h263-video", true
	case 2980:
		return "wimd", true
	case 2981:
		return "mylxamport", true
	case 2982:
		return "iwb-whiteboard", true
	case 2983:
		return "netplan", true
	case 2984:
		return "hpidsadmin", true
	case 2985:
		return "hpidsagent", true
	case 2986:
		return "stonefalls", true
	case 2987:
		return "identify", true
	case 2988:
		return "hippad", true
	case 2989:
		return "zarkov", true
	case 2990:
		return "boscap", true
	case 2991:
		return "wkstn-mon", true
	case 2992:
		return "avenyo", true
	case 2993:
		return "veritas-vis1", true
	case 2994:
		return "veritas-vis2", true
	case 2995:
		return "idrs", true
	case 2996:
		return "vsixml", true
	case 2997:
		return "rebol", true
	case 2998:
		return "realsecure", true
	case 2999:
		return "remoteware-un", true
	case 3000:
		return "hbci", true
	case 3001:
		return "origo-native", true
	case 3002:
		return "exlm-agent", true
	case 3003:
		return "cgms", true
	case 3004:
		return "csoftragent", true
	case 3005:
		return "geniuslm", true
	case 3006:
		return "ii-admin", true
	case 3007:
		return "lotusmtap", true
	case 3008:
		return "midnight-tech", true
	case 3009:
		return "pxc-ntfy", true
	case 3010:
		return "gw", true
	case 3011:
		return "trusted-web", true
	case 3012:
		return "twsdss", true
	case 3013:
		return "gilatskysurfer", true
	case 3014:
		return "broker-service", true
	case 3015:
		return "nati-dstp", true
	case 3016:
		return "notify-srvr", true
	case 3017:
		return "event-listener", true
	case 3018:
		return "srvc-registry", true
	case 3019:
		return "resource-mgr", true
	case 3020:
		return "cifs", true
	case 3021:
		return "agriserver", true
	case 3022:
		return "csregagent", true
	case 3023:
		return "magicnotes", true
	case 3024:
		return "nds-sso", true
	case 3025:
		return "arepa-raft", true
	case 3026:
		return "agri-gateway", true
	case 3027:
		return "LiebDevMgmt-C", true
	case 3028:
		return "LiebDevMgmt-DM", true
	case 3029:
		return "LiebDevMgmt-A", true
	case 3030:
		return "arepa-cas", true
	case 3031:
		return "eppc", true
	case 3032:
		return "redwood-chat", true
	case 3033:
		return "pdb", true
	case 3034:
		return "osmosis-aeea", true
	case 3035:
		return "fjsv-gssagt", true
	case 3036:
		return "hagel-dump", true
	case 3037:
		return "hp-san-mgmt", true
	case 3038:
		return "santak-ups", true
	case 3039:
		return "cogitate", true
	case 3040:
		return "tomato-springs", true
	case 3041:
		return "di-traceware", true
	case 3042:
		return "journee", true
	case 3043:
		return "brp", true
	case 3044:
		return "epp", true
	case 3045:
		return "responsenet", true
	case 3046:
		return "di-ase", true
	case 3047:
		return "hlserver", true
	case 3048:
		return "pctrader", true
	case 3049:
		return "nsws", true
	case 3050:
		return "gds-db", true
	case 3051:
		return "galaxy-server", true
	case 3052:
		return "apc-3052", true
	case 3053:
		return "dsom-server", true
	case 3054:
		return "amt-cnf-prot", true
	case 3055:
		return "policyserver", true
	case 3056:
		return "cdl-server", true
	case 3057:
		return "goahead-fldup", true
	case 3058:
		return "videobeans", true
	case 3059:
		return "qsoft", true
	case 3060:
		return "interserver", true
	case 3061:
		return "cautcpd", true
	case 3062:
		return "ncacn-ip-tcp", true
	case 3063:
		return "ncadg-ip-udp", true
	case 3064:
		return "rprt", true
	case 3065:
		return "slinterbase", true
	case 3066:
		return "netattachsdmp", true
	case 3067:
		return "fjhpjp", true
	case 3068:
		return "ls3bcast", true
	case 3069:
		return "ls3", true
	case 3070:
		return "mgxswitch", true
	case 3071:
		return "xplat-replicate", true
	case 3072:
		return "csd-monitor", true
	case 3073:
		return "vcrp", true
	case 3074:
		return "xbox", true
	case 3075:
		return "orbix-locator", true
	case 3076:
		return "orbix-config", true
	case 3077:
		return "orbix-loc-ssl", true
	case 3078:
		return "orbix-cfg-ssl", true
	case 3079:
		return "lv-frontpanel", true
	case 3080:
		return "stm-pproc", true
	case 3081:
		return "tl1-lv", true
	case 3082:
		return "tl1-raw", true
	case 3083:
		return "tl1-telnet", true
	case 3084:
		return "itm-mccs", true
	case 3085:
		return "pcihreq", true
	case 3086:
		return "jdl-dbkitchen", true
	case 3087:
		return "asoki-sma", true
	case 3088:
		return "xdtp", true
	case 3089:
		return "ptk-alink", true
	case 3090:
		return "stss", true
	case 3091:
		return "1ci-smcs", true
	case 3093:
		return "rapidmq-center", true
	case 3094:
		return "rapidmq-reg", true
	case 3095:
		return "panasas", true
	case 3096:
		return "ndl-aps", true
	case 3098:
		return "umm-port", true
	case 3099:
		return "chmd", true
	case 3100:
		return "opcon-xps", true
	case 3101:
		return "hp-pxpib", true
	case 3102:
		return "slslavemon", true
	case 3103:
		return "autocuesmi", true
	case 3104:
		return "autocuelog", true
	case 3105:
		return "cardbox", true
	case 3106:
		return "cardbox-http", true
	case 3107:
		return "business", true
	case 3108:
		return "geolocate", true
	case 3109:
		return "personnel", true
	case 3110:
		return "sim-control", true
	case 3111:
		return "wsynch", true
	case 3112:
		return "ksysguard", true
	case 3113:
		return "cs-auth-svr", true
	case 3114:
		return "ccmad", true
	case 3115:
		return "mctet-master", true
	case 3116:
		return "mctet-gateway", true
	case 3117:
		return "mctet-jserv", true
	case 3118:
		return "pkagent", true
	case 3119:
		return "d2000kernel", true
	case 3120:
		return "d2000webserver", true
	case 3121:
		return "pcmk-remote", true
	case 3122:
		return "vtr-emulator", true
	case 3123:
		return "edix", true
	case 3124:
		return "beacon-port", true
	case 3125:
		return "a13-an", true
	case 3127:
		return "ctx-bridge", true
	case 3128:
		return "ndl-aas", true
	case 3129:
		return "netport-id", true
	case 3130:
		return "icpv2", true
	case 3131:
		return "netbookmark", true
	case 3132:
		return "ms-rule-engine", true
	case 3133:
		return "prism-deploy", true
	case 3134:
		return "ecp", true
	case 3135:
		return "peerbook-port", true
	case 3136:
		return "grubd", true
	case 3137:
		return "rtnt-1", true
	case 3138:
		return "rtnt-2", true
	case 3139:
		return "incognitorv", true
	case 3140:
		return "ariliamulti", true
	case 3141:
		return "vmodem", true
	case 3142:
		return "rdc-wh-eos", true
	case 3143:
		return "seaview", true
	case 3144:
		return "tarantella", true
	case 3145:
		return "csi-lfap", true
	case 3146:
		return "bears-02", true
	case 3147:
		return "rfio", true
	case 3148:
		return "nm-game-admin", true
	case 3149:
		return "nm-game-server", true
	case 3150:
		return "nm-asses-admin", true
	case 3151:
		return "nm-assessor", true
	case 3152:
		return "feitianrockey", true
	case 3153:
		return "s8-client-port", true
	case 3154:
		return "ccmrmi", true
	case 3155:
		return "jpegmpeg", true
	case 3156:
		return "indura", true
	case 3157:
		return "e3consultants", true
	case 3158:
		return "stvp", true
	case 3159:
		return "navegaweb-port", true
	case 3160:
		return "tip-app-server", true
	case 3161:
		return "doc1lm", true
	case 3162:
		return "sflm", true
	case 3163:
		return "res-sap", true
	case 3164:
		return "imprs", true
	case 3165:
		return "newgenpay", true
	case 3166:
		return "sossecollector", true
	case 3167:
		return "nowcontact", true
	case 3168:
		return "poweronnud", true
	case 3169:
		return "serverview-as", true
	case 3170:
		return "serverview-asn", true
	case 3171:
		return "serverview-gf", true
	case 3172:
		return "serverview-rm", true
	case 3173:
		return "serverview-icc", true
	case 3174:
		return "armi-server", true
	case 3175:
		return "t1-e1-over-ip", true
	case 3176:
		return "ars-master", true
	case 3177:
		return "phonex-port", true
	case 3178:
		return "radclientport", true
	case 3179:
		return "h2gf-w-2m", true
	case 3180:
		return "mc-brk-srv", true
	case 3181:
		return "bmcpatrolagent", true
	case 3182:
		return "bmcpatrolrnvu", true
	case 3183:
		return "cops-tls", true
	case 3184:
		return "apogeex-port", true
	case 3185:
		return "smpppd", true
	case 3186:
		return "iiw-port", true
	case 3187:
		return "odi-port", true
	case 3188:
		return "brcm-comm-port", true
	case 3189:
		return "pcle-infex", true
	case 3190:
		return "csvr-proxy", true
	case 3191:
		return "csvr-sslproxy", true
	case 3192:
		return "firemonrcc", true
	case 3193:
		return "spandataport", true
	case 3194:
		return "magbind", true
	case 3195:
		return "ncu-1", true
	case 3196:
		return "ncu-2", true
	case 3197:
		return "embrace-dp-s", true
	case 3198:
		return "embrace-dp-c", true
	case 3199:
		return "dmod-workspace", true
	case 3200:
		return "tick-port", true
	case 3201:
		return "cpq-tasksmart", true
	case 3202:
		return "intraintra", true
	case 3203:
		return "netwatcher-mon", true
	case 3204:
		return "netwatcher-db", true
	case 3205:
		return "isns", true
	case 3206:
		return "ironmail", true
	case 3207:
		return "vx-auth-port", true
	case 3208:
		return "pfu-prcallback", true
	case 3209:
		return "netwkpathengine", true
	case 3210:
		return "flamenco-proxy", true
	case 3211:
		return "avsecuremgmt", true
	case 3212:
		return "surveyinst", true
	case 3213:
		return "neon24x7", true
	case 3214:
		return "jmq-daemon-1", true
	case 3215:
		return "jmq-daemon-2", true
	case 3216:
		return "ferrari-foam", true
	case 3217:
		return "unite", true
	case 3218:
		return "smartpackets", true
	case 3219:
		return "wms-messenger", true
	case 3220:
		return "xnm-ssl", true
	case 3221:
		return "xnm-clear-text", true
	case 3222:
		return "glbp", true
	case 3223:
		return "digivote", true
	case 3224:
		return "aes-discovery", true
	case 3225:
		return "fcip-port", true
	case 3226:
		return "isi-irp", true
	case 3227:
		return "dwnmshttp", true
	case 3228:
		return "dwmsgserver", true
	case 3229:
		return "global-cd-port", true
	case 3230:
		return "sftdst-port", true
	case 3231:
		return "vidigo", true
	case 3232:
		return "mdtp", true
	case 3233:
		return "whisker", true
	case 3234:
		return "alchemy", true
	case 3235:
		return "mdap-port", true
	case 3236:
		return "apparenet-ts", true
	case 3237:
		return "apparenet-tps", true
	case 3238:
		return "apparenet-as", true
	case 3239:
		return "apparenet-ui", true
	case 3240:
		return "triomotion", true
	case 3241:
		return "sysorb", true
	case 3242:
		return "sdp-id-port", true
	case 3243:
		return "timelot", true
	case 3244:
		return "onesaf", true
	case 3245:
		return "vieo-fe", true
	case 3246:
		return "dvt-system", true
	case 3247:
		return "dvt-data", true
	case 3248:
		return "procos-lm", true
	case 3249:
		return "ssp", true
	case 3250:
		return "hicp", true
	case 3251:
		return "sysscanner", true
	case 3252:
		return "dhe", true
	case 3253:
		return "pda-data", true
	case 3254:
		return "pda-sys", true
	case 3255:
		return "semaphore", true
	case 3256:
		return "cpqrpm-agent", true
	case 3257:
		return "cpqrpm-server", true
	case 3258:
		return "ivecon-port", true
	case 3259:
		return "epncdp2", true
	case 3260:
		return "iscsi-target", true
	case 3261:
		return "winshadow", true
	case 3262:
		return "necp", true
	case 3263:
		return "ecolor-imager", true
	case 3264:
		return "ccmail", true
	case 3265:
		return "altav-tunnel", true
	case 3266:
		return "ns-cfg-server", true
	case 3267:
		return "ibm-dial-out", true
	case 3268:
		return "msft-gc", true
	case 3269:
		return "msft-gc-ssl", true
	case 3270:
		return "verismart", true
	case 3271:
		return "csoft-prev", true
	case 3272:
		return "user-manager", true
	case 3273:
		return "sxmp", true
	case 3274:
		return "ordinox-server", true
	case 3275:
		return "samd", true
	case 3276:
		return "maxim-asics", true
	case 3277:
		return "awg-proxy", true
	case 3278:
		return "lkcmserver", true
	case 3279:
		return "admind", true
	case 3280:
		return "vs-server", true
	case 3281:
		return "sysopt", true
	case 3282:
		return "datusorb", true
	case 3283:
		return "Apple Remote Desktop (Net Assistant)", true
	case 3284:
		return "4talk", true
	case 3285:
		return "plato", true
	case 3286:
		return "e-net", true
	case 3287:
		return "directvdata", true
	case 3288:
		return "cops", true
	case 3289:
		return "enpc", true
	case 3290:
		return "caps-lm", true
	case 3291:
		return "sah-lm", true
	case 3292:
		return "cart-o-rama", true
	case 3293:
		return "fg-fps", true
	case 3294:
		return "fg-gip", true
	case 3295:
		return "dyniplookup", true
	case 3296:
		return "rib-slm", true
	case 3297:
		return "cytel-lm", true
	case 3298:
		return "deskview", true
	case 3299:
		return "pdrncs", true
	case 3300:
		return "ceph", true
	case 3301:
		return "tarantool", true
	case 3302:
		return "mcs-fastmail", true
	case 3303:
		return "opsession-clnt", true
	case 3304:
		return "opsession-srvr", true
	case 3305:
		return "odette-ftp", true
	case 3306:
		return "mysql", true
	case 3307:
		return "opsession-prxy", true
	case 3308:
		return "tns-server", true
	case 3309:
		return "tns-adv", true
	case 3310:
		return "dyna-access", true
	case 3311:
		return "mcns-tel-ret", true
	case 3312:
		return "appman-server", true
	case 3313:
		return "uorb", true
	case 3314:
		return "uohost", true
	case 3315:
		return "cdid", true
	case 3316:
		return "aicc-cmi", true
	case 3317:
		return "vsaiport", true
	case 3318:
		return "ssrip", true
	case 3319:
		return "sdt-lmd", true
	case 3320:
		return "officelink2000", true
	case 3321:
		return "vnsstr", true
	case 3326:
		return "sftu", true
	case 3327:
		return "bbars", true
	case 3328:
		return "egptlm", true
	case 3329:
		return "hp-device-disc", true
	case 3330:
		return "mcs-calypsoicf", true
	case 3331:
		return "mcs-messaging", true
	case 3332:
		return "mcs-mailsvr", true
	case 3333:
		return "dec-notes", true
	case 3334:
		return "directv-web", true
	case 3335:
		return "directv-soft", true
	case 3336:
		return "directv-tick", true
	case 3337:
		return "directv-catlg", true
	case 3338:
		return "anet-b", true
	case 3339:
		return "anet-l", true
	case 3340:
		return "anet-m", true
	case 3341:
		return "anet-h", true
	case 3342:
		return "webtie", true
	case 3343:
		return "ms-cluster-net", true
	case 3344:
		return "bnt-manager", true
	case 3345:
		return "influence", true
	case 3346:
		return "trnsprntproxy", true
	case 3347:
		return "phoenix-rpc", true
	case 3348:
		return "pangolin-laser", true
	case 3349:
		return "chevinservices", true
	case 3350:
		return "findviatv", true
	case 3351:
		return "btrieve", true
	case 3352:
		return "ssql", true
	case 3353:
		return "fatpipe", true
	case 3354:
		return "suitjd", true
	case 3355:
		return "ordinox-dbase", true
	case 3356:
		return "upnotifyps", true
	case 3357:
		return "adtech-test", true
	case 3358:
		return "mpsysrmsvr", true
	case 3359:
		return "wg-netforce", true
	case 3360:
		return "kv-server", true
	case 3361:
		return "kv-agent", true
	case 3362:
		return "dj-ilm", true
	case 3363:
		return "nati-vi-server", true
	case 3364:
		return "creativeserver", true
	case 3365:
		return "contentserver", true
	case 3366:
		return "creativepartnr", true
	case 3372:
		return "tip2", true
	case 3373:
		return "lavenir-lm", true
	case 3374:
		return "cluster-disc", true
	case 3375:
		return "vsnm-agent", true
	case 3376:
		return "cdbroker", true
	case 3377:
		return "cogsys-lm", true
	case 3378:
		return "wsicopy", true
	case 3379:
		return "socorfs", true
	case 3380:
		return "sns-channels", true
	case 3381:
		return "geneous", true
	case 3382:
		return "fujitsu-neat", true
	case 3383:
		return "esp-lm", true
	case 3384:
		return "hp-clic", true
	case 3385:
		return "qnxnetman", true
	case 3386:
		return "gprs-data", true
	case 3387:
		return "backroomnet", true
	case 3388:
		return "cbserver", true
	case 3389:
		return "ms-wbt-server", true
	case 3390:
		return "dsc", true
	case 3391:
		return "savant", true
	case 3392:
		return "efi-lm", true
	case 3393:
		return "d2k-tapestry1", true
	case 3394:
		return "d2k-tapestry2", true
	case 3395:
		return "dyna-lm", true
	case 3396:
		return "printer-agent", true
	case 3397:
		return "cloanto-lm", true
	case 3398:
		return "mercantile", true
	case 3399:
		return "csms", true
	case 3400:
		return "csms2", true
	case 3401:
		return "filecast", true
	case 3402:
		return "fxaengine-net", true
	case 3405:
		return "nokia-ann-ch1", true
	case 3406:
		return "nokia-ann-ch2", true
	case 3407:
		return "ldap-admin", true
	case 3408:
		return "BESApi", true
	case 3409:
		return "networklens", true
	case 3410:
		return "networklenss", true
	case 3411:
		return "biolink-auth", true
	case 3412:
		return "xmlblaster", true
	case 3413:
		return "svnet", true
	case 3414:
		return "wip-port", true
	case 3415:
		return "bcinameservice", true
	case 3416:
		return "commandport", true
	case 3417:
		return "csvr", true
	case 3418:
		return "rnmap", true
	case 3419:
		return "softaudit", true
	case 3420:
		return "ifcp-port", true
	case 3421:
		return "bmap", true
	case 3422:
		return "rusb-sys-port", true
	case 3423:
		return "xtrm", true
	case 3424:
		return "xtrms", true
	case 3425:
		return "agps-port", true
	case 3426:
		return "arkivio", true
	case 3427:
		return "websphere-snmp", true
	case 3428:
		return "twcss", true
	case 3429:
		return "gcsp", true
	case 3430:
		return "ssdispatch", true
	case 3431:
		return "ndl-als", true
	case 3432:
		return "osdcp", true
	case 3433:
		return "opnet-smp", true
	case 3434:
		return "opencm", true
	case 3435:
		return "pacom", true
	case 3436:
		return "gc-config", true
	case 3437:
		return "autocueds", true
	case 3438:
		return "spiral-admin", true
	case 3439:
		return "hri-port", true
	case 3440:
		return "ans-console", true
	case 3441:
		return "connect-client", true
	case 3442:
		return "connect-server", true
	case 3443:
		return "ov-nnm-websrv", true
	case 3444:
		return "denali-server", true
	case 3445:
		return "monp", true
	case 3446:
		return "3comfaxrpc", true
	case 3447:
		return "directnet", true
	case 3448:
		return "dnc-port", true
	case 3449:
		return "hotu-chat", true
	case 3450:
		return "castorproxy", true
	case 3451:
		return "asam", true
	case 3452:
		return "sabp-signal", true
	case 3453:
		return "pscupd", true
	case 3454:
		return "mira", true
	case 3455:
		return "prsvp", true
	case 3456:
		return "vat", true
	case 3457:
		return "vat-control", true
	case 3458:
		return "d3winosfi", true
	case 3459:
		return "integral", true
	case 3460:
		return "edm-manager", true
	case 3461:
		return "edm-stager", true
	case 3462:
		return "edm-std-notify", true
	case 3463:
		return "edm-adm-notify", true
	case 3464:
		return "edm-mgr-sync", true
	case 3465:
		return "edm-mgr-cntrl", true
	case 3466:
		return "workflow", true
	case 3467:
		return "rcst", true
	case 3468:
		return "ttcmremotectrl", true
	case 3469:
		return "pluribus", true
	case 3470:
		return "jt400", true
	case 3471:
		return "jt400-ssl", true
	case 3472:
		return "jaugsremotec-1", true
	case 3473:
		return "jaugsremotec-2", true
	case 3474:
		return "ttntspauto", true
	case 3475:
		return "genisar-port", true
	case 3476:
		return "nppmp", true
	case 3477:
		return "ecomm", true
	case 3478:
		return "stun", true
	case 3479:
		return "twrpc", true
	case 3480:
		return "plethora", true
	case 3481:
		return "cleanerliverc", true
	case 3482:
		return "vulture", true
	case 3483:
		return "slim-devices", true
	case 3484:
		return "gbs-stp", true
	case 3485:
		return "celatalk", true
	case 3486:
		return "ifsf-hb-port", true
	case 3487:
		return "ltctcp", true
	case 3488:
		return "fs-rh-srv", true
	case 3489:
		return "dtp-dia", true
	case 3490:
		return "colubris", true
	case 3491:
		return "swr-port", true
	case 3492:
		return "tvdumtray-port", true
	case 3493:
		return "nut", true
	case 3494:
		return "ibm3494", true
	case 3495:
		return "seclayer-tcp", true
	case 3496:
		return "seclayer-tls", true
	case 3497:
		return "ipether232port", true
	case 3498:
		return "dashpas-port", true
	case 3499:
		return "sccip-media", true
	case 3500:
		return "rtmp-port", true
	case 3501:
		return "isoft-p2p", true
	case 3502:
		return "avinstalldisc", true
	case 3503:
		return "lsp-ping", true
	case 3504:
		return "ironstorm", true
	case 3505:
		return "ccmcomm", true
	case 3506:
		return "apc-3506", true
	case 3507:
		return "nesh-broker", true
	case 3508:
		return "interactionweb", true
	case 3509:
		return "vt-ssl", true
	case 3510:
		return "xss-port", true
	case 3511:
		return "webmail-2", true
	case 3512:
		return "aztec", true
	case 3513:
		return "arcpd", true
	case 3514:
		return "must-p2p", true
	case 3515:
		return "must-backplane", true
	case 3516:
		return "smartcard-port", true
	case 3517:
		return "802-11-iapp", true
	case 3518:
		return "artifact-msg", true
	case 3519:
		return "nvmsgd", true
	case 3520:
		return "galileolog", true
	case 3521:
		return "mc3ss", true
	case 3522:
		return "nssocketport", true
	case 3523:
		return "odeumservlink", true
	case 3524:
		return "ecmport", true
	case 3525:
		return "eisport", true
	case 3526:
		return "starquiz-port", true
	case 3527:
		return "beserver-msg-q", true
	case 3528:
		return "jboss-iiop", true
	case 3529:
		return "jboss-iiop-ssl", true
	case 3530:
		return "gf", true
	case 3531:
		return "joltid", true
	case 3532:
		return "raven-rmp", true
	case 3533:
		return "raven-rdp", true
	case 3534:
		return "urld-port", true
	case 3535:
		return "ms-la", true
	case 3536:
		return "snac", true
	case 3537:
		return "ni-visa-remote", true
	case 3538:
		return "ibm-diradm", true
	case 3539:
		return "ibm-diradm-ssl", true
	case 3540:
		return "pnrp-port", true
	case 3541:
		return "voispeed-port", true
	case 3542:
		return "hacl-monitor", true
	case 3543:
		return "qftest-lookup", true
	case 3544:
		return "teredo", true
	case 3545:
		return "camac", true
	case 3547:
		return "symantec-sim", true
	case 3548:
		return "interworld", true
	case 3549:
		return "tellumat-nms", true
	case 3550:
		return "ssmpp", true
	case 3551:
		return "apcupsd", true
	case 3552:
		return "taserver", true
	case 3553:
		return "rbr-discovery", true
	case 3554:
		return "questnotify", true
	case 3555:
		return "razor", true
	case 3556:
		return "sky-transport", true
	case 3557:
		return "personalos-001", true
	case 3558:
		return "mcp-port", true
	case 3559:
		return "cctv-port", true
	case 3560:
		return "iniserve-port", true
	case 3561:
		return "bmc-onekey", true
	case 3562:
		return "sdbproxy", true
	case 3563:
		return "watcomdebug", true
	case 3564:
		return "esimport", true
	case 3565:
		return "m2pa", true
	case 3566:
		return "quest-data-hub", true
	case 3567:
		return "dof-eps", true
	case 3568:
		return "dof-tunnel-sec", true
	case 3569:
		return "mbg-ctrl", true
	case 3570:
		return "mccwebsvr-port", true
	case 3571:
		return "megardsvr-port", true
	case 3572:
		return "megaregsvrport", true
	case 3573:
		return "tag-ups-1", true
	case 3574:
		return "dmaf-server", true
	case 3575:
		return "ccm-port", true
	case 3576:
		return "cmc-port", true
	case 3577:
		return "config-port", true
	case 3578:
		return "data-port", true
	case 3579:
		return "ttat3lb", true
	case 3580:
		return "nati-svrloc", true
	case 3581:
		return "kfxaclicensing", true
	case 3582:
		return "press", true
	case 3583:
		return "canex-watch", true
	case 3584:
		return "u-dbap", true
	case 3585:
		return "emprise-lls", true
	case 3586:
		return "emprise-lsc", true
	case 3587:
		return "p2pgroup", true
	case 3588:
		return "sentinel", true
	case 3589:
		return "isomair", true
	case 3590:
		return "wv-csp-sms", true
	case 3591:
		return "gtrack-server", true
	case 3592:
		return "gtrack-ne", true
	case 3593:
		return "bpmd", true
	case 3594:
		return "mediaspace", true
	case 3595:
		return "shareapp", true
	case 3596:
		return "iw-mmogame", true
	case 3597:
		return "a14", true
	case 3598:
		return "a15", true
	case 3599:
		return "quasar-server", true
	case 3600:
		return "trap-daemon", true
	case 3601:
		return "visinet-gui", true
	case 3602:
		return "infiniswitchcl", true
	case 3603:
		return "int-rcv-cntrl", true
	case 3604:
		return "bmc-jmx-port", true
	case 3605:
		return "comcam-io", true
	case 3606:
		return "splitlock", true
	case 3607:
		return "precise-i3", true
	case 3608:
		return "trendchip-dcp", true
	case 3609:
		return "cpdi-pidas-cm", true
	case 3610:
		return "echonet", true
	case 3611:
		return "six-degrees", true
	case 3612:
		return "dataprotector", true
	case 3613:
		return "alaris-disc", true
	case 3614:
		return "sigma-port", true
	case 3615:
		return "start-network", true
	case 3616:
		return "cd3o-protocol", true
	case 3617:
		return "sharp-server", true
	case 3618:
		return "aairnet-1", true
	case 3619:
		return "aairnet-2", true
	case 3620:
		return "ep-pcp", true
	case 3621:
		return "ep-nsp", true
	case 3622:
		return "ff-lr-port", true
	case 3623:
		return "haipe-discover", true
	case 3624:
		return "dist-upgrade", true
	case 3625:
		return "volley", true
	case 3626:
		return "bvcdaemon-port", true
	case 3627:
		return "jamserverport", true
	case 3628:
		return "ept-machine", true
	case 3629:
		return "escvpnet", true
	case 3630:
		return "cs-remote-db", true
	case 3631:
		return "cs-services", true
	case 3632:
		return "distcc", true
	case 3633:
		return "wacp", true
	case 3634:
		return "hlibmgr", true
	case 3635:
		return "sdo", true
	case 3636:
		return "servistaitsm", true
	case 3637:
		return "scservp", true
	case 3638:
		return "ehp-backup", true
	case 3639:
		return "xap-ha", true
	case 3640:
		return "netplay-port1", true
	case 3641:
		return "netplay-port2", true
	case 3642:
		return "juxml-port", true
	case 3643:
		return "audiojuggler", true
	case 3644:
		return "ssowatch", true
	case 3645:
		return "cyc", true
	case 3646:
		return "xss-srv-port", true
	case 3647:
		return "splitlock-gw", true
	case 3648:
		return "fjcp", true
	case 3649:
		return "nmmp", true
	case 3650:
		return "prismiq-plugin", true
	case 3651:
		return "xrpc-registry", true
	case 3652:
		return "vxcrnbuport", true
	case 3653:
		return "tsp", true
	case 3654:
		return "vaprtm", true
	case 3655:
		return "abatemgr", true
	case 3656:
		return "abatjss", true
	case 3657:
		return "immedianet-bcn", true
	case 3658:
		return "ps-ams", true
	case 3659:
		return "apple-sasl", true
	case 3660:
		return "can-nds-ssl", true
	case 3661:
		return "can-ferret-ssl", true
	case 3662:
		return "pserver", true
	case 3663:
		return "dtp", true
	case 3664:
		return "ups-engine", true
	case 3665:
		return "ent-engine", true
	case 3666:
		return "eserver-pap", true
	case 3667:
		return "infoexch", true
	case 3668:
		return "dell-rm-port", true
	case 3669:
		return "casanswmgmt", true
	case 3670:
		return "smile", true
	case 3671:
		return "efcp", true
	case 3672:
		return "lispworks-orb", true
	case 3673:
		return "mediavault-gui", true
	case 3674:
		return "wininstall-ipc", true
	case 3675:
		return "calltrax", true
	case 3676:
		return "va-pacbase", true
	case 3677:
		return "roverlog", true
	case 3678:
		return "ipr-dglt", true
	case 3679:
		return "Escale (Newton Dock)", true
	case 3680:
		return "npds-tracker", true
	case 3681:
		return "bts-x73", true
	case 3682:
		return "cas-mapi", true
	case 3683:
		return "bmc-ea", true
	case 3684:
		return "faxstfx-port", true
	case 3685:
		return "dsx-agent", true
	case 3686:
		return "tnmpv2", true
	case 3687:
		return "simple-push", true
	case 3688:
		return "simple-push-s", true
	case 3689:
		return "daap", true
	case 3690:
		return "svn", true
	case 3691:
		return "magaya-network", true
	case 3692:
		return "intelsync", true
	case 3693:
		return "easl", true
	case 3695:
		return "bmc-data-coll", true
	case 3696:
		return "telnetcpcd", true
	case 3697:
		return "nw-license", true
	case 3698:
		return "sagectlpanel", true
	case 3699:
		return "kpn-icw", true
	case 3700:
		return "lrs-paging", true
	case 3701:
		return "netcelera", true
	case 3702:
		return "ws-discovery", true
	case 3703:
		return "adobeserver-3", true
	case 3704:
		return "adobeserver-4", true
	case 3705:
		return "adobeserver-5", true
	case 3706:
		return "rt-event", true
	case 3707:
		return "rt-event-s", true
	case 3708:
		return "sun-as-iiops", true
	case 3709:
		return "ca-idms", true
	case 3710:
		return "portgate-auth", true
	case 3711:
		return "edb-server2", true
	case 3712:
		return "sentinel-ent", true
	case 3713:
		return "tftps", true
	case 3714:
		return "delos-dms", true
	case 3715:
		return "anoto-rendezv", true
	case 3716:
		return "wv-csp-sms-cir", true
	case 3717:
		return "wv-csp-udp-cir", true
	case 3718:
		return "opus-services", true
	case 3719:
		return "itelserverport", true
	case 3720:
		return "ufastro-instr", true
	case 3721:
		return "xsync", true
	case 3722:
		return "xserveraid", true
	case 3723:
		return "sychrond", true
	case 3724:
		return "blizwow", true
	case 3725:
		return "na-er-tip", true
	case 3726:
		return "array-manager", true
	case 3727:
		return "e-mdu", true
	case 3728:
		return "e-woa", true
	case 3729:
		return "fksp-audit", true
	case 3730:
		return "client-ctrl", true
	case 3731:
		return "smap", true
	case 3732:
		return "m-wnn", true
	case 3733:
		return "multip-msg", true
	case 3734:
		return "synel-data", true
	case 3735:
		return "pwdis", true
	case 3736:
		return "rs-rmi", true
	case 3737:
		return "xpanel", true
	case 3738:
		return "versatalk", true
	case 3739:
		return "launchbird-lm", true
	case 3740:
		return "heartbeat", true
	case 3741:
		return "wysdma", true
	case 3742:
		return "cst-port", true
	case 3743:
		return "ipcs-command", true
	case 3744:
		return "sasg", true
	case 3745:
		return "gw-call-port", true
	case 3746:
		return "linktest", true
	case 3747:
		return "linktest-s", true
	case 3748:
		return "webdata", true
	case 3749:
		return "cimtrak", true
	case 3750:
		return "cbos-ip-port", true
	case 3751:
		return "gprs-cube", true
	case 3752:
		return "vipremoteagent", true
	case 3753:
		return "nattyserver", true
	case 3754:
		return "timestenbroker", true
	case 3755:
		return "sas-remote-hlp", true
	case 3756:
		return "canon-capt", true
	case 3757:
		return "grf-port", true
	case 3758:
		return "apw-registry", true
	case 3759:
		return "exapt-lmgr", true
	case 3760:
		return "adtempusclient", true
	case 3761:
		return "gsakmp", true
	case 3762:
		return "gbs-smp", true
	case 3763:
		return "xo-wave", true
	case 3764:
		return "mni-prot-rout", true
	case 3765:
		return "rtraceroute", true
	case 3766:
		return "sitewatch-s", true
	case 3767:
		return "listmgr-port", true
	case 3768:
		return "rblcheckd", true
	case 3769:
		return "haipe-otnk", true
	case 3770:
		return "cindycollab", true
	case 3771:
		return "paging-port", true
	case 3772:
		return "ctp", true
	case 3773:
		return "ctdhercules", true
	case 3774:
		return "zicom", true
	case 3775:
		return "ispmmgr", true
	case 3776:
		return "dvcprov-port", true
	case 3777:
		return "jibe-eb", true
	case 3778:
		return "c-h-it-port", true
	case 3779:
		return "cognima", true
	case 3780:
		return "nnp", true
	case 3781:
		return "abcvoice-port", true
	case 3782:
		return "iso-tp0s", true
	case 3783:
		return "bim-pem", true
	case 3784:
		return "bfd-control", true
	case 3785:
		return "bfd-echo", true
	case 3786:
		return "upstriggervsw", true
	case 3787:
		return "fintrx", true
	case 3788:
		return "isrp-port", true
	case 3789:
		return "remotedeploy", true
	case 3790:
		return "quickbooksrds", true
	case 3791:
		return "tvnetworkvideo", true
	case 3792:
		return "sitewatch", true
	case 3793:
		return "dcsoftware", true
	case 3794:
		return "jaus", true
	case 3795:
		return "myblast", true
	case 3796:
		return "spw-dialer", true
	case 3797:
		return "idps", true
	case 3798:
		return "minilock", true
	case 3799:
		return "radius-dynauth", true
	case 3800:
		return "pwgpsi", true
	case 3801:
		return "ibm-mgr", true
	case 3802:
		return "vhd", true
	case 3803:
		return "soniqsync", true
	case 3804:
		return "iqnet-port", true
	case 3805:
		return "tcpdataserver", true
	case 3806:
		return "wsmlb", true
	case 3807:
		return "spugna", true
	case 3808:
		return "sun-as-iiops-ca", true
	case 3809:
		return "apocd", true
	case 3810:
		return "wlanauth", true
	case 3811:
		return "amp", true
	case 3812:
		return "neto-wol-server", true
	case 3813:
		return "rap-ip", true
	case 3814:
		return "neto-dcs", true
	case 3815:
		return "lansurveyorxml", true
	case 3816:
		return "sunlps-http", true
	case 3817:
		return "tapeware", true
	case 3818:
		return "crinis-hb", true
	case 3819:
		return "epl-slp", true
	case 3820:
		return "scp", true
	case 3821:
		return "pmcp", true
	case 3822:
		return "acp-discovery", true
	case 3823:
		return "acp-conduit", true
	case 3824:
		return "acp-policy", true
	case 3825:
		return "ffserver", true
	case 3826:
		return "warmux", true
	case 3827:
		return "netmpi", true
	case 3828:
		return "neteh", true
	case 3829:
		return "neteh-ext", true
	case 3830:
		return "cernsysmgmtagt", true
	case 3831:
		return "dvapps", true
	case 3832:
		return "xxnetserver", true
	case 3833:
		return "aipn-auth", true
	case 3834:
		return "spectardata", true
	case 3835:
		return "spectardb", true
	case 3836:
		return "markem-dcp", true
	case 3837:
		return "mkm-discovery", true
	case 3838:
		return "sos", true
	case 3839:
		return "amx-rms", true
	case 3840:
		return "flirtmitmir", true
	case 3841:
		return "shiprush-db-svr", true
	case 3842:
		return "nhci", true
	case 3843:
		return "quest-agent", true
	case 3844:
		return "rnm", true
	case 3845:
		return "v-one-spp", true
	case 3846:
		return "an-pcp", true
	case 3847:
		return "msfw-control", true
	case 3848:
		return "item", true
	case 3849:
		return "spw-dnspreload", true
	case 3850:
		return "qtms-bootstrap", true
	case 3851:
		return "spectraport", true
	case 3852:
		return "sse-app-config", true
	case 3853:
		return "sscan", true
	case 3854:
		return "stryker-com", true
	case 3855:
		return "opentrac", true
	case 3856:
		return "informer", true
	case 3857:
		return "trap-port", true
	case 3858:
		return "trap-port-mom", true
	case 3859:
		return "nav-port", true
	case 3860:
		return "sasp", true
	case 3861:
		return "winshadow-hd", true
	case 3862:
		return "giga-pocket", true
	case 3863:
		return "asap-tcp", true
	case 3864:
		return "asap-tcp-tls", true
	case 3865:
		return "xpl", true
	case 3866:
		return "dzdaemon", true
	case 3867:
		return "dzoglserver", true
	case 3868:
		return "diameter", true
	case 3869:
		return "ovsam-mgmt", true
	case 3870:
		return "ovsam-d-agent", true
	case 3871:
		return "avocent-adsap", true
	case 3872:
		return "oem-agent", true
	case 3873:
		return "fagordnc", true
	case 3874:
		return "sixxsconfig", true
	case 3875:
		return "pnbscada", true
	case 3876:
		return "dl-agent", true
	case 3877:
		return "xmpcr-interface", true
	case 3878:
		return "fotogcad", true
	case 3879:
		return "appss-lm", true
	case 3880:
		return "igrs", true
	case 3881:
		return "idac", true
	case 3882:
		return "msdts1", true
	case 3883:
		return "vrpn", true
	case 3884:
		return "softrack-meter", true
	case 3885:
		return "topflow-ssl", true
	case 3886:
		return "nei-management", true
	case 3887:
		return "ciphire-data", true
	case 3888:
		return "ciphire-serv", true
	case 3889:
		return "dandv-tester", true
	case 3890:
		return "ndsconnect", true
	case 3891:
		return "rtc-pm-port", true
	case 3892:
		return "pcc-image-port", true
	case 3893:
		return "cgi-starapi", true
	case 3894:
		return "syam-agent", true
	case 3895:
		return "syam-smc", true
	case 3896:
		return "sdo-tls", true
	case 3897:
		return "sdo-ssh", true
	case 3898:
		return "senip", true
	case 3899:
		return "itv-control", true
	case 3900:
		return "udt-os", true
	case 3901:
		return "nimsh", true
	case 3902:
		return "nimaux", true
	case 3903:
		return "charsetmgr", true
	case 3904:
		return "omnilink-port", true
	case 3905:
		return "mupdate", true
	case 3906:
		return "topovista-data", true
	case 3907:
		return "imoguia-port", true
	case 3908:
		return "hppronetman", true
	case 3909:
		return "surfcontrolcpa", true
	case 3910:
		return "prnrequest", true
	case 3911:
		return "prnstatus", true
	case 3912:
		return "gbmt-stars", true
	case 3913:
		return "listcrt-port", true
	case 3914:
		return "listcrt-port-2", true
	case 3915:
		return "agcat", true
	case 3916:
		return "wysdmc", true
	case 3917:
		return "aftmux", true
	case 3918:
		return "pktcablemmcops", true
	case 3919:
		return "hyperip", true
	case 3920:
		return "exasoftport1", true
	case 3921:
		return "herodotus-net", true
	case 3922:
		return "sor-update", true
	case 3923:
		return "symb-sb-port", true
	case 3924:
		return "mpl-gprs-port", true
	case 3925:
		return "zmp", true
	case 3926:
		return "winport", true
	case 3927:
		return "natdataservice", true
	case 3928:
		return "netboot-pxe", true
	case 3929:
		return "smauth-port", true
	case 3930:
		return "syam-webserver", true
	case 3931:
		return "msr-plugin-port", true
	case 3932:
		return "dyn-site", true
	case 3933:
		return "plbserve-port", true
	case 3934:
		return "sunfm-port", true
	case 3935:
		return "sdp-portmapper", true
	case 3936:
		return "mailprox", true
	case 3937:
		return "dvbservdsc", true
	case 3938:
		return "dbcontrol-agent", true
	case 3939:
		return "aamp", true
	case 3940:
		return "xecp-node", true
	case 3941:
		return "homeportal-web", true
	case 3942:
		return "srdp", true
	case 3943:
		return "tig", true
	case 3944:
		return "sops", true
	case 3945:
		return "emcads", true
	case 3946:
		return "backupedge", true
	case 3947:
		return "ccp", true
	case 3948:
		return "apdap", true
	case 3949:
		return "drip", true
	case 3950:
		return "namemunge", true
	case 3951:
		return "pwgippfax", true
	case 3952:
		return "i3-sessionmgr", true
	case 3953:
		return "xmlink-connect", true
	case 3954:
		return "adrep", true
	case 3955:
		return "p2pcommunity", true
	case 3956:
		return "gvcp", true
	case 3957:
		return "mqe-broker", true
	case 3958:
		return "mqe-agent", true
	case 3959:
		return "treehopper", true
	case 3960:
		return "bess", true
	case 3961:
		return "proaxess", true
	case 3962:
		return "sbi-agent", true
	case 3963:
		return "thrp", true
	case 3964:
		return "sasggprs", true
	case 3965:
		return "ati-ip-to-ncpe", true
	case 3966:
		return "bflckmgr", true
	case 3967:
		return "ppsms", true
	case 3968:
		return "ianywhere-dbns", true
	case 3969:
		return "landmarks", true
	case 3970:
		return "lanrevagent", true
	case 3971:
		return "lanrevserver", true
	case 3972:
		return "iconp", true
	case 3973:
		return "progistics", true
	case 3974:
		return "xk22", true
	case 3975:
		return "airshot", true
	case 3976:
		return "opswagent", true
	case 3977:
		return "opswmanager", true
	case 3978:
		return "secure-cfg-svr", true
	case 3979:
		return "smwan", true
	case 3981:
		return "starfish", true
	case 3982:
		return "eis", true
	case 3983:
		return "eisp", true
	case 3984:
		return "mapper-nodemgr", true
	case 3985:
		return "mapper-mapethd", true
	case 3986:
		return "mapper-ws-ethd", true
	case 3987:
		return "centerline", true
	case 3988:
		return "dcs-config", true
	case 3989:
		return "bv-queryengine", true
	case 3990:
		return "bv-is", true
	case 3991:
		return "bv-smcsrv", true
	case 3992:
		return "bv-ds", true
	case 3993:
		return "bv-agent", true
	case 3995:
		return "iss-mgmt-ssl", true
	case 3996:
		return "abcsoftware", true
	case 3997:
		return "agentsease-db", true
	case 3998:
		return "dnx", true
	case 3999:
		return "nvcnet", true
	case 4000:
		return "terabase", true
	case 4001:
		return "newoak", true
	case 4002:
		return "pxc-spvr-ft", true
	case 4003:
		return "pxc-splr-ft", true
	case 4004:
		return "pxc-roid", true
	case 4005:
		return "pxc-pin", true
	case 4006:
		return "pxc-spvr", true
	case 4007:
		return "pxc-splr", true
	case 4008:
		return "netcheque", true
	case 4009:
		return "chimera-hwm", true
	case 4010:
		return "samsung-unidex", true
	case 4011:
		return "altserviceboot", true
	case 4012:
		return "pda-gate", true
	case 4013:
		return "acl-manager", true
	case 4014:
		return "taiclock", true
	case 4015:
		return "talarian-mcast1", true
	case 4016:
		return "talarian-mcast2", true
	case 4017:
		return "talarian-mcast3", true
	case 4018:
		return "talarian-mcast4", true
	case 4019:
		return "talarian-mcast5", true
	case 4020:
		return "trap", true
	case 4021:
		return "nexus-portal", true
	case 4022:
		return "dnox", true
	case 4023:
		return "esnm-zoning", true
	case 4024:
		return "tnp1-port", true
	case 4025:
		return "partimage", true
	case 4026:
		return "as-debug", true
	case 4027:
		return "bxp", true
	case 4028:
		return "dtserver-port", true
	case 4029:
		return "ip-qsig", true
	case 4030:
		return "jdmn-port", true
	case 4031:
		return "suucp", true
	case 4032:
		return "vrts-auth-port", true
	case 4033:
		return "sanavigator", true
	case 4034:
		return "ubxd", true
	case 4035:
		return "wap-push-http", true
	case 4036:
		return "wap-push-https", true
	case 4037:
		return "ravehd", true
	case 4038:
		return "fazzt-ptp", true
	case 4039:
		return "fazzt-admin", true
	case 4040:
		return "yo-main", true
	case 4041:
		return "houston", true
	case 4042:
		return "ldxp", true
	case 4043:
		return "nirp", true
	case 4044:
		return "ltp", true
	case 4045:
		return "npp", true
	case 4046:
		return "acp-proto", true
	case 4047:
		return "ctp-state", true
	case 4049:
		return "wafs", true
	case 4050:
		return "cisco-wafs", true
	case 4051:
		return "cppdp", true
	case 4052:
		return "interact", true
	case 4053:
		return "ccu-comm-1", true
	case 4054:
		return "ccu-comm-2", true
	case 4055:
		return "ccu-comm-3", true
	case 4056:
		return "lms", true
	case 4057:
		return "wfm", true
	case 4058:
		return "kingfisher", true
	case 4059:
		return "dlms-cosem", true
	case 4060:
		return "dsmeter-iatc", true
	case 4061:
		return "ice-location", true
	case 4062:
		return "ice-slocation", true
	case 4063:
		return "ice-router", true
	case 4064:
		return "ice-srouter", true
	case 4065:
		return "avanti-cdp", true
	case 4066:
		return "pmas", true
	case 4067:
		return "idp", true
	case 4068:
		return "ipfltbcst", true
	case 4069:
		return "minger", true
	case 4070:
		return "tripe", true
	case 4071:
		return "aibkup", true
	case 4072:
		return "zieto-sock", true
	case 4073:
		return "iRAPP", true
	case 4074:
		return "cequint-cityid", true
	case 4075:
		return "perimlan", true
	case 4076:
		return "seraph", true
	case 4078:
		return "cssp", true
	case 4079:
		return "santools", true
	case 4080:
		return "lorica-in", true
	case 4081:
		return "lorica-in-sec", true
	case 4082:
		return "lorica-out", true
	case 4083:
		return "lorica-out-sec", true
	case 4085:
		return "ezmessagesrv", true
	case 4087:
		return "applusservice", true
	case 4088:
		return "npsp", true
	case 4089:
		return "opencore", true
	case 4090:
		return "omasgport", true
	case 4091:
		return "ewinstaller", true
	case 4092:
		return "ewdgs", true
	case 4093:
		return "pvxpluscs", true
	case 4094:
		return "sysrqd", true
	case 4095:
		return "xtgui", true
	case 4096:
		return "bre", true
	case 4097:
		return "patrolview", true
	case 4098:
		return "drmsfsd", true
	case 4099:
		return "dpcp", true
	case 4100:
		return "igo-incognito", true
	case 4101:
		return "brlp-0", true
	case 4102:
		return "brlp-1", true
	case 4103:
		return "brlp-2", true
	case 4104:
		return "brlp-3", true
	case 4105:
		return "shofar", true
	case 4106:
		return "synchronite", true
	case 4107:
		return "j-ac", true
	case 4108:
		return "accel", true
	case 4109:
		return "izm", true
	case 4110:
		return "g2tag", true
	case 4111:
		return "xgrid", true
	case 4112:
		return "apple-vpns-rp", true
	case 4113:
		return "aipn-reg", true
	case 4114:
		return "jomamqmonitor", true
	case 4115:
		return "cds", true
	case 4116:
		return "smartcard-tls", true
	case 4117:
		return "hillrserv", true
	case 4118:
		return "netscript", true
	case 4119:
		return "assuria-slm", true
	case 4120:
		return "minirem", true
	case 4121:
		return "e-builder", true
	case 4122:
		return "fprams", true
	case 4123:
		return "z-wave", true
	case 4124:
		return "tigv2", true
	case 4125:
		return "opsview-envoy", true
	case 4126:
		return "ddrepl", true
	case 4127:
		return "unikeypro", true
	case 4128:
		return "nufw", true
	case 4129:
		return "nuauth", true
	case 4130:
		return "fronet", true
	case 4131:
		return "stars", true
	case 4132:
		return "nuts-dem", true
	case 4133:
		return "nuts-bootp", true
	case 4134:
		return "nifty-hmi", true
	case 4135:
		return "cl-db-attach", true
	case 4136:
		return "cl-db-request", true
	case 4137:
		return "cl-db-remote", true
	case 4138:
		return "nettest", true
	case 4139:
		return "thrtx", true
	case 4140:
		return "cedros-fds", true
	case 4141:
		return "oirtgsvc", true
	case 4142:
		return "oidocsvc", true
	case 4143:
		return "oidsr", true
	case 4145:
		return "vvr-control", true
	case 4146:
		return "tgcconnect", true
	case 4147:
		return "vrxpservman", true
	case 4148:
		return "hhb-handheld", true
	case 4149:
		return "agslb", true
	case 4150:
		return "PowerAlert-nsa", true
	case 4151:
		return "menandmice-noh", true
	case 4152:
		return "idig-mux", true
	case 4153:
		return "mbl-battd", true
	case 4154:
		return "atlinks", true
	case 4155:
		return "bzr", true
	case 4156:
		return "stat-results", true
	case 4157:
		return "stat-scanner", true
	case 4158:
		return "stat-cc", true
	case 4159:
		return "nss", true
	case 4160:
		return "jini-discovery", true
	case 4161:
		return "omscontact", true
	case 4162:
		return "omstopology", true
	case 4163:
		return "silverpeakpeer", true
	case 4164:
		return "silverpeakcomm", true
	case 4165:
		return "altcp", true
	case 4166:
		return "joost", true
	case 4167:
		return "ddgn", true
	case 4168:
		return "pslicser", true
	case 4169:
		return "iadt", true
	case 4170:
		return "d-cinema-csp", true
	case 4171:
		return "ml-svnet", true
	case 4172:
		return "pcoip", true
	case 4174:
		return "smcluster", true
	case 4175:
		return "bccp", true
	case 4176:
		return "tl-ipcproxy", true
	case 4177:
		return "wello", true
	case 4178:
		return "storman", true
	case 4179:
		return "MaxumSP", true
	case 4180:
		return "httpx", true
	case 4181:
		return "macbak", true
	case 4182:
		return "pcptcpservice", true
	case 4183:
		return "cyborgnet", true
	case 4184:
		return "universe-suite", true
	case 4185:
		return "wcpp", true
	case 4186:
		return "boxbackupstore", true
	case 4187:
		return "csc-proxy", true
	case 4188:
		return "vatata", true
	case 4189:
		return "pcep", true
	case 4190:
		return "sieve", true
	case 4192:
		return "azeti", true
	case 4193:
		return "pvxplusio", true
	case 4194:
		return "spdm", true
	case 4195:
		return "aws-wsp", true
	case 4197:
		return "hctl", true
	case 4199:
		return "eims-admin", true
	case 4300:
		return "corelccam", true
	case 4301:
		return "d-data", true
	case 4302:
		return "d-data-control", true
	case 4303:
		return "srcp", true
	case 4304:
		return "owserver", true
	case 4305:
		return "batman", true
	case 4306:
		return "pinghgl", true
	case 4307:
		return "trueconf", true
	case 4308:
		return "compx-lockview", true
	case 4309:
		return "dserver", true
	case 4310:
		return "mirrtex", true
	case 4311:
		return "p6ssmc", true
	case 4312:
		return "pscl-mgt", true
	case 4313:
		return "perrla", true
	case 4314:
		return "choiceview-agt", true
	case 4316:
		return "choiceview-clt", true
	case 4317:
		return "opentelemetry", true
	case 4319:
		return "fox-skytale", true
	case 4320:
		return "fdt-rcatp", true
	case 4321:
		return "rwhois", true
	case 4322:
		return "trim-event", true
	case 4323:
		return "trim-ice", true
	case 4325:
		return "geognosisadmin", true
	case 4326:
		return "geognosis", true
	case 4327:
		return "jaxer-web", true
	case 4328:
		return "jaxer-manager", true
	case 4329:
		return "publiqare-sync", true
	case 4330:
		return "dey-sapi", true
	case 4331:
		return "ktickets-rest", true
	case 4332:
		return "getty-focus", true
	case 4333:
		return "ahsp", true
	case 4334:
		return "netconf-ch-ssh", true
	case 4335:
		return "netconf-ch-tls", true
	case 4336:
		return "restconf-ch-tls", true
	case 4340:
		return "gaia", true
	case 4343:
		return "unicall", true
	case 4344:
		return "vinainstall", true
	case 4345:
		return "m4-network-as", true
	case 4346:
		return "elanlm", true
	case 4347:
		return "lansurveyor", true
	case 4348:
		return "itose", true
	case 4349:
		return "fsportmap", true
	case 4350:
		return "net-device", true
	case 4351:
		return "plcy-net-svcs", true
	case 4352:
		return "pjlink", true
	case 4353:
		return "f5-iquery", true
	case 4354:
		return "qsnet-trans", true
	case 4355:
		return "qsnet-workst", true
	case 4356:
		return "qsnet-assist", true
	case 4357:
		return "qsnet-cond", true
	case 4358:
		return "qsnet-nucl", true
	case 4359:
		return "omabcastltkm", true
	case 4360:
		return "matrix-vnet", true
	case 4368:
		return "wxbrief", true
	case 4369:
		return "epmd", true
	case 4370:
		return "elpro-tunnel", true
	case 4371:
		return "l2c-control", true
	case 4372:
		return "l2c-data", true
	case 4373:
		return "remctl", true
	case 4374:
		return "psi-ptt", true
	case 4375:
		return "tolteces", true
	case 4376:
		return "bip", true
	case 4377:
		return "cp-spxsvr", true
	case 4378:
		return "cp-spxdpy", true
	case 4379:
		return "ctdb", true
	case 4389:
		return "xandros-cms", true
	case 4390:
		return "wiegand", true
	case 4391:
		return "apwi-imserver", true
	case 4392:
		return "apwi-rxserver", true
	case 4393:
		return "apwi-rxspooler", true
	case 4395:
		return "omnivisionesx", true
	case 4396:
		return "fly", true
	case 4400:
		return "ds-srv", true
	case 4401:
		return "ds-srvr", true
	case 4402:
		return "ds-clnt", true
	case 4403:
		return "ds-user", true
	case 4404:
		return "ds-admin", true
	case 4405:
		return "ds-mail", true
	case 4406:
		return "ds-slp", true
	case 4407:
		return "nacagent", true
	case 4408:
		return "slscc", true
	case 4409:
		return "netcabinet-com", true
	case 4410:
		return "itwo-server", true
	case 4411:
		return "found", true
	case 4413:
		return "avi-nms", true
	case 4414:
		return "updog", true
	case 4415:
		return "brcd-vr-req", true
	case 4416:
		return "pjj-player", true
	case 4417:
		return "workflowdir", true
	case 4419:
		return "cbp", true
	case 4420:
		return "nvme", true
	case 4421:
		return "scaleft", true
	case 4422:
		return "tsepisp", true
	case 4423:
		return "thingkit", true
	case 4425:
		return "netrockey6", true
	case 4426:
		return "beacon-port-2", true
	case 4427:
		return "drizzle", true
	case 4428:
		return "omviserver", true
	case 4429:
		return "omviagent", true
	case 4430:
		return "rsqlserver", true
	case 4431:
		return "wspipe", true
	case 4432:
		return "l-acoustics", true
	case 4433:
		return "vop", true
	case 4442:
		return "saris", true
	case 4443:
		return "pharos", true
	case 4444:
		return "krb524", true
	case 4445:
		return "upnotifyp", true
	case 4446:
		return "n1-fwp", true
	case 4447:
		return "n1-rmgmt", true
	case 4448:
		return "asc-slmd", true
	case 4449:
		return "privatewire", true
	case 4450:
		return "camp", true
	case 4451:
		return "ctisystemmsg", true
	case 4452:
		return "ctiprogramload", true
	case 4453:
		return "nssalertmgr", true
	case 4454:
		return "nssagentmgr", true
	case 4455:
		return "prchat-user", true
	case 4456:
		return "prchat-server", true
	case 4457:
		return "prRegister", true
	case 4458:
		return "mcp", true
	case 4460:
		return "ntske", true
	case 4484:
		return "hpssmgmt", true
	case 4485:
		return "assyst-dr", true
	case 4486:
		return "icms", true
	case 4487:
		return "prex-tcp", true
	case 4488:
		return "awacs-ice", true
	case 4500:
		return "ipsec-nat-t", true
	case 4535:
		return "ehs", true
	case 4536:
		return "ehs-ssl", true
	case 4537:
		return "wssauthsvc", true
	case 4538:
		return "swx-gate", true
	case 4545:
		return "worldscores", true
	case 4546:
		return "sf-lm", true
	case 4547:
		return "lanner-lm", true
	case 4548:
		return "synchromesh", true
	case 4549:
		return "aegate", true
	case 4550:
		return "gds-adppiw-db", true
	case 4551:
		return "ieee-mih", true
	case 4552:
		return "menandmice-mon", true
	case 4553:
		return "icshostsvc", true
	case 4554:
		return "msfrs", true
	case 4555:
		return "rsip", true
	case 4556:
		return "dtn-bundle", true
	case 4559:
		return "hylafax", true
	case 4563:
		return "amahi-anywhere", true
	case 4566:
		return "kwtc", true
	case 4567:
		return "tram", true
	case 4568:
		return "bmc-reporting", true
	case 4569:
		return "iax", true
	case 4570:
		return "deploymentmap", true
	case 4573:
		return "cardifftec-back", true
	case 4590:
		return "rid", true
	case 4591:
		return "l3t-at-an", true
	case 4593:
		return "ipt-anri-anri", true
	case 4594:
		return "ias-session", true
	case 4595:
		return "ias-paging", true
	case 4596:
		return "ias-neighbor", true
	case 4597:
		return "a21-an-1xbs", true
	case 4598:
		return "a16-an-an", true
	case 4599:
		return "a17-an-an", true
	case 4600:
		return "piranha1", true
	case 4601:
		return "piranha2", true
	case 4602:
		return "mtsserver", true
	case 4603:
		return "menandmice-upg", true
	case 4604:
		return "irp", true
	case 4605:
		return "sixchat", true
	case 4606:
		return "sixid", true
	case 4646:
		return "dots-signal", true
	case 4658:
		return "playsta2-app", true
	case 4659:
		return "playsta2-lob", true
	case 4660:
		return "smaclmgr", true
	case 4661:
		return "kar2ouche", true
	case 4662:
		return "oms", true
	case 4663:
		return "noteit", true
	case 4664:
		return "ems", true
	case 4665:
		return "contclientms", true
	case 4666:
		return "eportcomm", true
	case 4667:
		return "mmacomm", true
	case 4668:
		return "mmaeds", true
	case 4669:
		return "eportcommdata", true
	case 4670:
		return "light", true
	case 4671:
		return "acter", true
	case 4672:
		return "rfa", true
	case 4673:
		return "cxws", true
	case 4674:
		return "appiq-mgmt", true
	case 4675:
		return "dhct-status", true
	case 4676:
		return "dhct-alerts", true
	case 4677:
		return "bcs", true
	case 4678:
		return "traversal", true
	case 4679:
		return "mgesupervision", true
	case 4680:
		return "mgemanagement", true
	case 4681:
		return "parliant", true
	case 4682:
		return "finisar", true
	case 4683:
		return "spike", true
	case 4684:
		return "rfid-rp1", true
	case 4685:
		return "autopac", true
	case 4686:
		return "msp-os", true
	case 4687:
		return "nst", true
	case 4688:
		return "mobile-p2p", true
	case 4689:
		return "altovacentral", true
	case 4690:
		return "prelude", true
	case 4691:
		return "mtn", true
	case 4692:
		return "conspiracy", true
	case 4700:
		return "netxms-agent", true
	case 4701:
		return "netxms-mgmt", true
	case 4702:
		return "netxms-sync", true
	case 4703:
		return "npqes-test", true
	case 4704:
		return "assuria-ins", true
	case 4711:
		return "trinity-dist", true
	case 4725:
		return "truckstar", true
	case 4727:
		return "fcis", true
	case 4728:
		return "capmux", true
	case 4730:
		return "gearman", true
	case 4731:
		return "remcap", true
	case 4733:
		return "resorcs", true
	case 4737:
		return "ipdr-sp", true
	case 4738:
		return "solera-lpn", true
	case 4739:
		return "ipfix", true
	case 4740:
		return "ipfixs", true
	case 4741:
		return "lumimgrd", true
	case 4742:
		return "sicct", true
	case 4743:
		return "openhpid", true
	case 4744:
		return "ifsp", true
	case 4745:
		return "fmp", true
	case 4749:
		return "profilemac", true
	case 4750:
		return "ssad", true
	case 4751:
		return "spocp", true
	case 4752:
		return "snap", true
	case 4753:
		return "simon", true
	case 4756:
		return "RDCenter", true
	case 4774:
		return "converge", true
	case 4784:
		return "bfd-multi-ctl", true
	case 4786:
		return "smart-install", true
	case 4787:
		return "sia-ctrl-plane", true
	case 4788:
		return "xmcp", true
	case 4792:
		return "unified-bus", true
	case 4800:
		return "iims", true
	case 4801:
		return "iwec", true
	case 4802:
		return "ilss", true
	case 4803:
		return "notateit", true
	case 4827:
		return "htcp", true
	case 4837:
		return "varadero-0", true
	case 4838:
		return "varadero-1", true
	case 4839:
		return "varadero-2", true
	case 4840:
		return "opcua-tcp", true
	case 4841:
		return "quosa", true
	case 4842:
		return "gw-asv", true
	case 4843:
		return "opcua-tls", true
	case 4844:
		return "gw-log", true
	case 4845:
		return "wcr-remlib", true
	case 4846:
		return "contamac-icm", true
	case 4847:
		return "wfc", true
	case 4848:
		return "appserv-http", true
	case 4849:
		return "appserv-https", true
	case 4850:
		return "sun-as-nodeagt", true
	case 4851:
		return "derby-repli", true
	case 4867:
		return "unify-debug", true
	case 4868:
		return "phrelay", true
	case 4869:
		return "phrelaydbg", true
	case 4870:
		return "cc-tracking", true
	case 4871:
		return "wired", true
	case 4876:
		return "tritium-can", true
	case 4877:
		return "lmcs", true
	case 4879:
		return "wsdl-event", true
	case 4880:
		return "hislip", true
	case 4883:
		return "wmlserver", true
	case 4884:
		return "hivestor", true
	case 4885:
		return "abbs", true
	case 4888:
		return "xcap-portal", true
	case 4889:
		return "xcap-control", true
	case 4894:
		return "lyskom", true
	case 4899:
		return "radmin-port", true
	case 4900:
		return "hfcs", true
	case 4901:
		return "flr-agent", true
	case 4902:
		return "magiccontrol", true
	case 4912:
		return "lutap", true
	case 4913:
		return "lutcp", true
	case 4914:
		return "bones", true
	case 4915:
		return "frcs", true
	case 4940:
		return "eq-office-4940", true
	case 4941:
		return "eq-office-4941", true
	case 4942:
		return "eq-office-4942", true
	case 4949:
		return "munin", true
	case 4950:
		return "sybasesrvmon", true
	case 4951:
		return "pwgwims", true
	case 4952:
		return "sagxtsds", true
	case 4953:
		return "dbsyncarbiter", true
	case 4969:
		return "ccss-qmm", true
	case 4970:
		return "ccss-qsm", true
	case 4971:
		return "burp", true
	case 4984:
		return "webyast", true
	case 4985:
		return "gerhcs", true
	case 4986:
		return "mrip", true
	case 4987:
		return "smar-se-port1", true
	case 4988:
		return "smar-se-port2", true
	case 4989:
		return "parallel", true
	case 4990:
		return "busycal", true
	case 4991:
		return "vrt", true
	case 4999:
		return "hfcs-manager", true
	case 5000:
		return "commplex-main", true
	case 5001:
		return "commplex-link", true
	case 5002:
		return "rfe", true
	case 5003:
		return "fmpro-internal", true
	case 5004:
		return "avt-profile-1", true
	case 5005:
		return "avt-profile-2", true
	case 5006:
		return "wsm-server", true
	case 5007:
		return "wsm-server-ssl", true
	case 5008:
		return "synapsis-edge", true
	case 5009:
		return "winfs", true
	case 5010:
		return "telelpathstart", true
	case 5011:
		return "telelpathattack", true
	case 5012:
		return "nsp", true
	case 5013:
		return "fmpro-v6", true
	case 5015:
		return "fmwp", true
	case 5020:
		return "zenginkyo-1", true
	case 5021:
		return "zenginkyo-2", true
	case 5022:
		return "mice", true
	case 5023:
		return "htuilsrv", true
	case 5024:
		return "scpi-telnet", true
	case 5025:
		return "scpi-raw", true
	case 5026:
		return "strexec-d", true
	case 5027:
		return "strexec-s", true
	case 5028:
		return "qvr", true
	case 5029:
		return "infobright", true
	case 5032:
		return "signacert-agent", true
	case 5033:
		return "jtnetd-server", true
	case 5034:
		return "jtnetd-status", true
	case 5042:
		return "asnaacceler8db", true
	case 5043:
		return "swxadmin", true
	case 5044:
		return "lxi-evntsvc", true
	case 5045:
		return "osp", true
	case 5048:
		return "texai", true
	case 5049:
		return "ivocalize", true
	case 5050:
		return "mmcc", true
	case 5051:
		return "ita-agent", true
	case 5052:
		return "ita-manager", true
	case 5053:
		return "rlm", true
	case 5054:
		return "rlm-admin", true
	case 5055:
		return "unot", true
	case 5056:
		return "intecom-ps1", true
	case 5057:
		return "intecom-ps2", true
	case 5059:
		return "sds", true
	case 5060:
		return "sip", true
	case 5061:
		return "sips", true
	case 5062:
		return "na-localise", true
	case 5063:
		return "csrpc", true
	case 5064:
		return "ca-1", true
	case 5065:
		return "ca-2", true
	case 5066:
		return "stanag-5066", true
	case 5067:
		return "authentx", true
	case 5068:
		return "bitforestsrv", true
	case 5069:
		return "i-net-2000-npr", true
	case 5070:
		return "vtsas", true
	case 5071:
		return "powerschool", true
	case 5072:
		return "ayiya", true
	case 5073:
		return "tag-pm", true
	case 5074:
		return "alesquery", true
	case 5075:
		return "pvaccess", true
	case 5080:
		return "onscreen", true
	case 5081:
		return "sdl-ets", true
	case 5082:
		return "qcp", true
	case 5083:
		return "qfp", true
	case 5084:
		return "llrp", true
	case 5085:
		return "encrypted-llrp", true
	case 5086:
		return "aprigo-cs", true
	case 5087:
		return "biotic", true
	case 5093:
		return "sentinel-lm", true
	case 5094:
		return "hart-ip", true
	case 5099:
		return "sentlm-srv2srv", true
	case 5100:
		return "socalia", true
	case 5101:
		return "talarian-tcp", true
	case 5102:
		return "oms-nonsecure", true
	case 5103:
		return "actifio-c2c", true
	case 5106:
		return "actifioudsagent", true
	case 5107:
		return "actifioreplic", true
	case 5111:
		return "taep-as-svc", true
	case 5112:
		return "pm-cmdsvr", true
	case 5114:
		return "ev-services", true
	case 5115:
		return "autobuild", true
	case 5117:
		return "gradecam", true
	case 5120:
		return "barracuda-bbs", true
	case 5133:
		return "nbt-pc", true
	case 5134:
		return "ppactivation", true
	case 5135:
		return "erp-scale", true
	case 5137:
		return "ctsd", true
	case 5145:
		return "rmonitor-secure", true
	case 5146:
		return "social-alarm", true
	case 5150:
		return "atmp", true
	case 5151:
		return "esri-sde", true
	case 5152:
		return "sde-discovery", true
	case 5154:
		return "bzflag", true
	case 5155:
		return "asctrl-agent", true
	case 5156:
		return "rugameonline", true
	case 5157:
		return "mediat", true
	case 5161:
		return "snmpssh", true
	case 5162:
		return "snmpssh-trap", true
	case 5163:
		return "sbackup", true
	case 5164:
		return "vpa", true
	case 5165:
		return "ife-icorp", true
	case 5166:
		return "winpcs", true
	case 5167:
		return "scte104", true
	case 5168:
		return "scte30", true
	case 5172:
		return "pcoip-mgmt", true
	case 5190:
		return "aol", true
	case 5191:
		return "aol-1", true
	case 5192:
		return "aol-2", true
	case 5193:
		return "aol-3", true
	case 5194:
		return "cpscomm", true
	case 5195:
		return "ampl-lic", true
	case 5196:
		return "ampl-tableproxy", true
	case 5197:
		return "tunstall-lwp", true
	case 5200:
		return "targus-getdata", true
	case 5201:
		return "targus-getdata1", true
	case 5202:
		return "targus-getdata2", true
	case 5203:
		return "targus-getdata3", true
	case 5209:
		return "nomad", true
	case 5215:
		return "noteza", true
	case 5221:
		return "3exmp", true
	case 5222:
		return "xmpp-client", true
	case 5223:
		return "hpvirtgrp", true
	case 5224:
		return "hpvirtctrl", true
	case 5225:
		return "hp-server", true
	case 5226:
		return "hp-status", true
	case 5227:
		return "perfd", true
	case 5228:
		return "hpvroom", true
	case 5229:
		return "jaxflow", true
	case 5230:
		return "jaxflow-data", true
	case 5231:
		return "crusecontrol", true
	case 5232:
		return "csedaemon", true
	case 5233:
		return "enfs", true
	case 5234:
		return "eenet", true
	case 5235:
		return "galaxy-network", true
	case 5236:
		return "padl2sim", true
	case 5237:
		return "mnet-discovery", true
	case 5242:
		return "attune", true
	case 5243:
		return "xycstatus", true
	case 5245:
		return "downtools", true
	case 5248:
		return "caacws", true
	case 5249:
		return "caaclang2", true
	case 5250:
		return "soagateway", true
	case 5251:
		return "caevms", true
	case 5252:
		return "movaz-ssc", true
	case 5253:
		return "kpdp", true
	case 5254:
		return "logcabin", true
	case 5264:
		return "3com-njack-1", true
	case 5265:
		return "3com-njack-2", true
	case 5269:
		return "xmpp-server", true
	case 5270:
		return "cartographerxmp", true
	case 5271:
		return "cuelink", true
	case 5272:
		return "pk", true
	case 5280:
		return "xmpp-bosh", true
	case 5281:
		return "undo-lm", true
	case 5282:
		return "transmit-port", true
	case 5298:
		return "presence", true
	case 5299:
		return "nlg-data", true
	case 5300:
		return "hacl-hb", true
	case 5301:
		return "hacl-gs", true
	case 5302:
		return "hacl-cfg", true
	case 5303:
		return "hacl-probe", true
	case 5304:
		return "hacl-local", true
	case 5305:
		return "hacl-test", true
	case 5306:
		return "sun-mc-grp", true
	case 5307:
		return "sco-aip", true
	case 5308:
		return "cfengine", true
	case 5309:
		return "jprinter", true
	case 5310:
		return "outlaws", true
	case 5312:
		return "permabit-cs", true
	case 5313:
		return "rrdp", true
	case 5314:
		return "opalis-rbt-ipc", true
	case 5315:
		return "hacl-poll", true
	case 5316:
		return "hpbladems", true
	case 5317:
		return "hpdevms", true
	case 5318:
		return "pkix-cmc", true
	case 5320:
		return "bsfserver-zn", true
	case 5321:
		return "bsfsvr-zn-ssl", true
	case 5343:
		return "kfserver", true
	case 5344:
		return "xkotodrcp", true
	case 5349:
		return "stuns", true
	case 5352:
		return "dns-llq", true
	case 5353:
		return "mdns", true
	case 5354:
		return "mdnsresponder", true
	case 5355:
		return "llmnr", true
	case 5356:
		return "ms-smlbiz", true
	case 5357:
		return "wsdapi", true
	case 5358:
		return "wsdapi-s", true
	case 5359:
		return "ms-alerter", true
	case 5360:
		return "ms-sideshow", true
	case 5361:
		return "ms-s-sideshow", true
	case 5362:
		return "serverwsd2", true
	case 5363:
		return "net-projection", true
	case 5397:
		return "stresstester", true
	case 5398:
		return "elektron-admin", true
	case 5399:
		return "securitychase", true
	case 5400:
		return "excerpt", true
	case 5401:
		return "excerpts", true
	case 5402:
		return "mftp", true
	case 5403:
		return "hpoms-ci-lstn", true
	case 5404:
		return "hpoms-dps-lstn", true
	case 5405:
		return "netsupport", true
	case 5406:
		return "systemics-sox", true
	case 5407:
		return "foresyte-clear", true
	case 5408:
		return "foresyte-sec", true
	case 5409:
		return "salient-dtasrv", true
	case 5410:
		return "salient-usrmgr", true
	case 5411:
		return "actnet", true
	case 5412:
		return "continuus", true
	case 5413:
		return "wwiotalk", true
	case 5414:
		return "statusd", true
	case 5415:
		return "ns-server", true
	case 5416:
		return "sns-gateway", true
	case 5417:
		return "sns-agent", true
	case 5418:
		return "mcntp", true
	case 5419:
		return "dj-ice", true
	case 5420:
		return "cylink-c", true
	case 5421:
		return "netsupport2", true
	case 5422:
		return "salient-mux", true
	case 5423:
		return "virtualuser", true
	case 5424:
		return "beyond-remote", true
	case 5425:
		return "br-channel", true
	case 5426:
		return "devbasic", true
	case 5427:
		return "sco-peer-tta", true
	case 5428:
		return "telaconsole", true
	case 5429:
		return "base", true
	case 5430:
		return "radec-corp", true
	case 5431:
		return "park-agent", true
	case 5432:
		return "postgresql", true
	case 5433:
		return "pyrrho", true
	case 5434:
		return "sgi-arrayd", true
	case 5435:
		return "sceanics", true
	case 5443:
		return "spss", true
	case 5445:
		return "smbdirect", true
	case 5450:
		return "tiepie", true
	case 5453:
		return "surebox", true
	case 5454:
		return "apc-5454", true
	case 5455:
		return "apc-5455", true
	case 5456:
		return "apc-5456", true
	case 5461:
		return "silkmeter", true
	case 5462:
		return "ttl-publisher", true
	case 5463:
		return "ttlpriceproxy", true
	case 5464:
		return "quailnet", true
	case 5465:
		return "netops-broker", true
	case 5470:
		return "apsolab-col", true
	case 5471:
		return "apsolab-cols", true
	case 5472:
		return "apsolab-tag", true
	case 5473:
		return "apsolab-tags", true
	case 5475:
		return "apsolab-data", true
	case 5500:
		return "fcp-addr-srvr1", true
	case 5501:
		return "fcp-addr-srvr2", true
	case 5502:
		return "fcp-srvr-inst1", true
	case 5503:
		return "fcp-srvr-inst2", true
	case 5504:
		return "fcp-cics-gw1", true
	case 5505:
		return "checkoutdb", true
	case 5506:
		return "amc", true
	case 5507:
		return "psl-management", true
	case 5540:
		return "matter", true
	case 5550:
		return "cbus", true
	case 5553:
		return "sgi-eventmond", true
	case 5554:
		return "sgi-esphttp", true
	case 5555:
		return "personal-agent", true
	case 5556:
		return "freeciv", true
	case 5557:
		return "farenet", true
	case 5565:
		return "dp-bura", true
	case 5566:
		return "westec-connect", true
	case 5567:
		return "dof-dps-mc-sec", true
	case 5568:
		return "sdt", true
	case 5569:
		return "rdmnet-ctrl", true
	case 5573:
		return "sdmmp", true
	case 5574:
		return "lsi-bobcat", true
	case 5575:
		return "ora-oap", true
	case 5579:
		return "fdtracks", true
	case 5580:
		return "tmosms0", true
	case 5581:
		return "tmosms1", true
	case 5582:
		return "fac-restore", true
	case 5583:
		return "tmo-icon-sync", true
	case 5584:
		return "bis-web", true
	case 5585:
		return "bis-sync", true
	case 5586:
		return "att-mt-sms", true
	case 5597:
		return "ininmessaging", true
	case 5598:
		return "mctfeed", true
	case 5599:
		return "esinstall", true
	case 5600:
		return "esmmanager", true
	case 5601:
		return "esmagent", true
	case 5602:
		return "a1-msc", true
	case 5603:
		return "a1-bs", true
	case 5604:
		return "a3-sdunode", true
	case 5605:
		return "a4-sdunode", true
	case 5618:
		return "efr", true
	case 5627:
		return "ninaf", true
	case 5628:
		return "htrust", true
	case 5629:
		return "symantec-sfdb", true
	case 5630:
		return "precise-comm", true
	case 5631:
		return "pcanywheredata", true
	case 5632:
		return "pcanywherestat", true
	case 5633:
		return "beorl", true
	case 5634:
		return "xprtld", true
	case 5635:
		return "sfmsso", true
	case 5636:
		return "sfm-db-server", true
	case 5637:
		return "cssc", true
	case 5638:
		return "flcrs", true
	case 5639:
		return "ics", true
	case 5646:
		return "vfmobile", true
	case 5666:
		return "nrpe", true
	case 5670:
		return "filemq", true
	case 5671:
		return "amqps", true
	case 5672:
		return "amqp", true
	case 5673:
		return "jms", true
	case 5674:
		return "hyperscsi-port", true
	case 5675:
		return "v5ua", true
	case 5676:
		return "raadmin", true
	case 5677:
		return "questdb2-lnchr", true
	case 5678:
		return "rrac", true
	case 5679:
		return "dccm", true
	case 5680:
		return "auriga-router", true
	case 5681:
		return "ncxcp", true
	case 5683:
		return "coap", true
	case 5684:
		return "coaps", true
	case 5688:
		return "ggz", true
	case 5689:
		return "qmvideo", true
	case 5693:
		return "rbsystem", true
	case 5696:
		return "kmip", true
	case 5700:
		return "supportassist", true
	case 5705:
		return "storageos", true
	case 5713:
		return "proshareaudio", true
	case 5714:
		return "prosharevideo", true
	case 5715:
		return "prosharedata", true
	case 5716:
		return "prosharerequest", true
	case 5717:
		return "prosharenotify", true
	case 5718:
		return "dpm", true
	case 5719:
		return "dpm-agent", true
	case 5720:
		return "ms-licensing", true
	case 5721:
		return "dtpt", true
	case 5722:
		return "msdfsr", true
	case 5723:
		return "omhs", true
	case 5724:
		return "omsdk", true
	case 5725:
		return "ms-ilm", true
	case 5726:
		return "ms-ilm-sts", true
	case 5727:
		return "asgenf", true
	case 5728:
		return "io-dist-data", true
	case 5729:
		return "openmail", true
	case 5730:
		return "unieng", true
	case 5741:
		return "ida-discover1", true
	case 5742:
		return "ida-discover2", true
	case 5743:
		return "watchdoc-pod", true
	case 5744:
		return "watchdoc", true
	case 5745:
		return "fcopy-server", true
	case 5746:
		return "fcopys-server", true
	case 5747:
		return "tunatic", true
	case 5748:
		return "tunalyzer", true
	case 5750:
		return "rscd", true
	case 5755:
		return "openmailg", true
	case 5757:
		return "x500ms", true
	case 5766:
		return "openmailns", true
	case 5767:
		return "s-openmail", true
	case 5768:
		return "openmailpxy", true
	case 5769:
		return "spramsca", true
	case 5770:
		return "spramsd", true
	case 5771:
		return "netagent", true
	case 5777:
		return "starfield-io", true
	case 5780:
		return "vts-rpc", true
	case 5781:
		return "3par-evts", true
	case 5782:
		return "3par-mgmt", true
	case 5783:
		return "3par-mgmt-ssl", true
	case 5785:
		return "3par-rcopy", true
	case 5793:
		return "xtreamx", true
	case 5798:
		return "enlabel-dpl", true
	case 5813:
		return "icmpd", true
	case 5814:
		return "spt-automation", true
	case 5820:
		return "autopassdaemon", true
	case 5841:
		return "shiprush-d-ch", true
	case 5842:
		return "reversion", true
	case 5859:
		return "wherehoo", true
	case 5863:
		return "ppsuitemsg", true
	case 5868:
		return "diameters", true
	case 5883:
		return "jute", true
	case 5900:
		return "rfb", true
	case 5903:
		return "ff-ice", true
	case 5904:
		return "ag-swim", true
	case 5905:
		return "asmgcs", true
	case 5906:
		return "rpas-c2", true
	case 5907:
		return "dsd", true
	case 5908:
		return "ipsma", true
	case 5909:
		return "agma", true
	case 5910:
		return "ats-atn", true
	case 5911:
		return "ats-acars", true
	case 5912:
		return "ais-met", true
	case 5913:
		return "aoc-acars", true
	case 5963:
		return "indy", true
	case 5968:
		return "mppolicy-v5", true
	case 5969:
		return "mppolicy-mgr", true
	case 5984:
		return "couchdb", true
	case 5985:
		return "wsman", true
	case 5986:
		return "wsmans", true
	case 5987:
		return "wbem-rmi", true
	case 5988:
		return "wbem-http", true
	case 5989:
		return "wbem-https", true
	case 5990:
		return "wbem-exp-https", true
	case 5991:
		return "nuxsl", true
	case 5992:
		return "consul-insight", true
	case 5993:
		return "cim-rs", true
	case 5994:
		return "rms-agent", true
	case 5999:
		return "cvsup", true
	case 6064:
		return "ndl-ahp-svc", true
	case 6065:
		return "winpharaoh", true
	case 6066:
		return "ewctsp", true
	case 6068:
		return "gsmp-ancp", true
	case 6069:
		return "trip", true
	case 6070:
		return "messageasap", true
	case 6071:
		return "ssdtp", true
	case 6072:
		return "diagnose-proc", true
	case 6073:
		return "directplay8", true
	case 6074:
		return "max", true
	case 6075:
		return "dpm-acm", true
	case 6076:
		return "msft-dpm-cert", true
	case 6077:
		return "iconstructsrv", true
	case 6084:
		return "reload-config", true
	case 6085:
		return "konspire2b", true
	case 6086:
		return "pdtp", true
	case 6087:
		return "ldss", true
	case 6088:
		return "doglms", true
	case 6099:
		return "raxa-mgmt", true
	case 6100:
		return "synchronet-db", true
	case 6101:
		return "synchronet-rtc", true
	case 6102:
		return "synchronet-upd", true
	case 6103:
		return "rets", true
	case 6104:
		return "dbdb", true
	case 6105:
		return "primaserver", true
	case 6106:
		return "mpsserver", true
	case 6107:
		return "etc-control", true
	case 6108:
		return "sercomm-scadmin", true
	case 6109:
		return "globecast-id", true
	case 6110:
		return "softcm", true
	case 6111:
		return "spc", true
	case 6112:
		return "dtspcd", true
	case 6113:
		return "dayliteserver", true
	case 6114:
		return "wrspice", true
	case 6115:
		return "xic", true
	case 6116:
		return "xtlserv", true
	case 6117:
		return "daylitetouch", true
	case 6121:
		return "spdy", true
	case 6122:
		return "bex-webadmin", true
	case 6123:
		return "backup-express", true
	case 6124:
		return "pnbs", true
	case 6130:
		return "damewaremobgtwy", true
	case 6133:
		return "nbt-wol", true
	case 6140:
		return "pulsonixnls", true
	case 6141:
		return "meta-corp", true
	case 6142:
		return "aspentec-lm", true
	case 6143:
		return "watershed-lm", true
	case 6144:
		return "statsci1-lm", true
	case 6145:
		return "statsci2-lm", true
	case 6146:
		return "lonewolf-lm", true
	case 6147:
		return "montage-lm", true
	case 6148:
		return "ricardo-lm", true
	case 6149:
		return "tal-pod", true
	case 6159:
		return "efb-aci", true
	case 6160:
		return "ecmp", true
	case 6161:
		return "patrol-ism", true
	case 6162:
		return "patrol-coll", true
	case 6163:
		return "pscribe", true
	case 6200:
		return "lm-x", true
	case 6209:
		return "qmtps", true
	case 6222:
		return "radmind", true
	case 6241:
		return "jeol-nsdtp-1", true
	case 6242:
		return "jeol-nsdtp-2", true
	case 6243:
		return "jeol-nsdtp-3", true
	case 6244:
		return "jeol-nsdtp-4", true
	case 6251:
		return "tl1-raw-ssl", true
	case 6252:
		return "tl1-ssh", true
	case 6253:
		return "crip", true
	case 6267:
		return "gld", true
	case 6268:
		return "grid", true
	case 6269:
		return "grid-alt", true
	case 6300:
		return "bmc-grx", true
	case 6301:
		return "bmc-ctd-ldap", true
	case 6306:
		return "ufmp", true
	case 6315:
		return "scup", true
	case 6316:
		return "abb-escp", true
	case 6317:
		return "nav-data-cmd", true
	case 6320:
		return "repsvc", true
	case 6321:
		return "emp-server1", true
	case 6322:
		return "emp-server2", true
	case 6324:
		return "hrd-ncs", true
	case 6325:
		return "dt-mgmtsvc", true
	case 6326:
		return "dt-vra", true
	case 6343:
		return "sflow", true
	case 6344:
		return "streletz", true
	case 6346:
		return "gnutella-svc", true
	case 6347:
		return "gnutella-rtr", true
	case 6350:
		return "adap", true
	case 6355:
		return "pmcs", true
	case 6360:
		return "metaedit-mu", true
	case 6370:
		return "metaedit-se", true
	case 6379:
		return "redis", true
	case 6382:
		return "metatude-mds", true
	case 6389:
		return "clariion-evr01", true
	case 6390:
		return "metaedit-ws", true
	case 6417:
		return "faxcomservice", true
	case 6418:
		return "syserverremote", true
	case 6419:
		return "svdrp", true
	case 6420:
		return "nim-vdrshell", true
	case 6421:
		return "nim-wan", true
	case 6432:
		return "pgbouncer", true
	case 6440:
		return "heliosd", true
	case 6442:
		return "tarp", true
	case 6443:
		return "sun-sr-https", true
	case 6444:
		return "sge-qmaster", true
	case 6445:
		return "sge-execd", true
	case 6446:
		return "mysql-proxy", true
	case 6455:
		return "skip-cert-recv", true
	case 6456:
		return "skip-cert-send", true
	case 6464:
		return "ieee11073-20701", true
	case 6471:
		return "lvision-lm", true
	case 6480:
		return "sun-sr-http", true
	case 6481:
		return "servicetags", true
	case 6482:
		return "ldoms-mgmt", true
	case 6483:
		return "SunVTS-RMI", true
	case 6484:
		return "sun-sr-jms", true
	case 6485:
		return "sun-sr-iiop", true
	case 6486:
		return "sun-sr-iiops", true
	case 6487:
		return "sun-sr-iiop-aut", true
	case 6488:
		return "sun-sr-jmx", true
	case 6489:
		return "sun-sr-admin", true
	case 6500:
		return "boks", true
	case 6501:
		return "boks-servc", true
	case 6502:
		return "boks-servm", true
	case 6503:
		return "boks-clntd", true
	case 6505:
		return "badm-priv", true
	case 6506:
		return "badm-pub", true
	case 6507:
		return "bdir-priv", true
	case 6508:
		return "bdir-pub", true
	case 6509:
		return "mgcs-mfp-port", true
	case 6510:
		return "mcer-port", true
	case 6513:
		return "netconf-tls", true
	case 6514:
		return "syslog-tls", true
	case 6515:
		return "elipse-rec", true
	case 6543:
		return "lds-distrib", true
	case 6544:
		return "lds-dump", true
	case 6547:
		return "apc-6547", true
	case 6548:
		return "apc-6548", true
	case 6549:
		return "apc-6549", true
	case 6550:
		return "fg-sysupdate", true
	case 6551:
		return "sum", true
	case 6556:
		return "checkmk-agent", true
	case 6558:
		return "xdsxdm", true
	case 6566:
		return "sane-port", true
	case 6568:
		return "canit-store", true
	case 6579:
		return "affiliate", true
	case 6580:
		return "parsec-master", true
	case 6581:
		return "parsec-peer", true
	case 6582:
		return "parsec-game", true
	case 6583:
		return "joaJewelSuite", true
	case 6600:
		return "mshvlm", true
	case 6601:
		return "mstmg-sstp", true
	case 6602:
		return "wsscomfrmwk", true
	case 6619:
		return "odette-ftps", true
	case 6620:
		return "kftp-data", true
	case 6621:
		return "kftp", true
	case 6622:
		return "mcftp", true
	case 6623:
		return "ktelnet", true
	case 6624:
		return "datascaler-db", true
	case 6625:
		return "datascaler-ctl", true
	case 6626:
		return "wago-service", true
	case 6627:
		return "nexgen", true
	case 6628:
		return "afesc-mc", true
	case 6629:
		return "nexgen-aux", true
	case 6632:
		return "mxodbc-connect", true
	case 6640:
		return "ovsdb", true
	case 6653:
		return "openflow", true
	case 6655:
		return "pcs-sf-ui-man", true
	case 6656:
		return "emgmsg", true
	case 6670:
		return "vocaltec-gold", true
	case 6671:
		return "p4p-portal", true
	case 6672:
		return "vision-server", true
	case 6673:
		return "vision-elmd", true
	case 6678:
		return "vfbp", true
	case 6679:
		return "osaut", true
	case 6687:
		return "clever-ctrace", true
	case 6688:
		return "clever-tcpip", true
	case 6689:
		return "tsa", true
	case 6690:
		return "cleverdetect", true
	case 6697:
		return "ircs-u", true
	case 6701:
		return "kti-icad-srvr", true
	case 6702:
		return "e-design-net", true
	case 6703:
		return "e-design-web", true
	case 6714:
		return "ibprotocol", true
	case 6715:
		return "fibotrader-com", true
	case 6716:
		return "princity-agent", true
	case 6767:
		return "bmc-perf-agent", true
	case 6768:
		return "bmc-perf-mgrd", true
	case 6769:
		return "adi-gxp-srvprt", true
	case 6770:
		return "plysrv-http", true
	case 6771:
		return "plysrv-https", true
	case 6777:
		return "ntz-tracker", true
	case 6778:
		return "ntz-p2p-storage", true
	case 6785:
		return "dgpf-exchg", true
	case 6786:
		return "smc-jmx", true
	case 6787:
		return "smc-admin", true
	case 6788:
		return "smc-http", true
	case 6789:
		return "radg", true
	case 6790:
		return "hnmp", true
	case 6791:
		return "hnm", true
	case 6801:
		return "acnet", true
	case 6817:
		return "pentbox-sim", true
	case 6831:
		return "ambit-lm", true
	case 6841:
		return "netmo-default", true
	case 6842:
		return "netmo-http", true
	case 6850:
		return "iccrushmore", true
	case 6868:
		return "acctopus-cc", true
	case 6888:
		return "muse", true
	case 6900:
		return "rtimeviewer", true
	case 6901:
		return "jetstream", true
	case 6924:
		return "split-ping", true
	case 6935:
		return "ethoscan", true
	case 6936:
		return "xsmsvc", true
	case 6946:
		return "bioserver", true
	case 6951:
		return "otlp", true
	case 6961:
		return "jmact3", true
	case 6962:
		return "jmevt2", true
	case 6963:
		return "swismgr1", true
	case 6964:
		return "swismgr2", true
	case 6965:
		return "swistrap", true
	case 6966:
		return "swispol", true
	case 6969:
		return "acmsoda", true
	case 6970:
		return "conductor", true
	case 6997:
		return "MobilitySrv", true
	case 6998:
		return "iatp-highpri", true
	case 6999:
		return "iatp-normalpri", true
	case 7000:
		return "afs3-fileserver", true
	case 7001:
		return "afs3-callback", true
	case 7002:
		return "afs3-prserver", true
	case 7003:
		return "afs3-vlserver", true
	case 7004:
		return "afs3-kaserver", true
	case 7005:
		return "afs3-volser", true
	case 7006:
		return "afs3-errors", true
	case 7007:
		return "afs3-bos", true
	case 7008:
		return "afs3-update", true
	case 7009:
		return "afs3-rmtsys", true
	case 7010:
		return "ups-onlinet", true
	case 7011:
		return "talon-disc", true
	case 7012:
		return "talon-engine", true
	case 7013:
		return "microtalon-dis", true
	case 7014:
		return "microtalon-com", true
	case 7015:
		return "talon-webserver", true
	case 7016:
		return "spg", true
	case 7017:
		return "grasp", true
	case 7018:
		return "fisa-svc", true
	case 7019:
		return "doceri-ctl", true
	case 7020:
		return "dpserve", true
	case 7021:
		return "dpserveadmin", true
	case 7022:
		return "ctdp", true
	case 7023:
		return "ct2nmcs", true
	case 7024:
		return "vmsvc", true
	case 7025:
		return "vmsvc-2", true
	case 7026:
		return "loreji-panel", true
	case 7030:
		return "op-probe", true
	case 7031:
		return "iposplanet", true
	case 7070:
		return "arcp", true
	case 7071:
		return "iwg1", true
	case 7072:
		return "iba-cfg", true
	case 7073:
		return "martalk", true
	case 7080:
		return "empowerid", true
	case 7099:
		return "lazy-ptop", true
	case 7100:
		return "font-service", true
	case 7101:
		return "elcn", true
	case 7117:
		return "rothaga", true
	case 7121:
		return "virprot-lm", true
	case 7123:
		return "snif", true
	case 7128:
		return "scenidm", true
	case 7129:
		return "scenccs", true
	case 7161:
		return "cabsm-comm", true
	case 7162:
		return "caistoragemgr", true
	case 7163:
		return "cacsambroker", true
	case 7164:
		return "fsr", true
	case 7165:
		return "doc-server", true
	case 7166:
		return "aruba-server", true
	case 7167:
		return "casrmagent", true
	case 7168:
		return "cnckadserver", true
	case 7169:
		return "ccag-pib", true
	case 7170:
		return "nsrp", true
	case 7171:
		return "drm-production", true
	case 7172:
		return "metalbend", true
	case 7173:
		return "zsecure", true
	case 7174:
		return "clutild", true
	case 7200:
		return "fodms", true
	case 7201:
		return "dlip", true
	case 7202:
		return "pon-ictp", true
	case 7215:
		return "PS-Server", true
	case 7216:
		return "PS-Capture-Pro", true
	case 7227:
		return "ramp", true
	case 7228:
		return "citrixupp", true
	case 7229:
		return "citrixuppg", true
	case 7234:
		return "asa-gateways", true
	case 7236:
		return "display", true
	case 7237:
		return "pads", true
	case 7244:
		return "frc-hicp", true
	case 7262:
		return "cnap", true
	case 7272:
		return "watchme-7272", true
	case 7273:
		return "oma-rlp", true
	case 7274:
		return "oma-rlp-s", true
	case 7275:
		return "oma-ulp", true
	case 7276:
		return "oma-ilp", true
	case 7277:
		return "oma-ilp-s", true
	case 7278:
		return "oma-dcdocbs", true
	case 7279:
		return "ctxlic", true
	case 7280:
		return "itactionserver1", true
	case 7281:
		return "itactionserver2", true
	case 7282:
		return "mzca-action", true
	case 7283:
		return "genstat", true
	case 7365:
		return "lcm-server", true
	case 7391:
		return "mindfilesys", true
	case 7392:
		return "mrssrendezvous", true
	case 7393:
		return "nfoldman", true
	case 7394:
		return "fse", true
	case 7395:
		return "winqedit", true
	case 7397:
		return "hexarc", true
	case 7400:
		return "rtps-discovery", true
	case 7401:
		return "rtps-dd-ut", true
	case 7402:
		return "rtps-dd-mt", true
	case 7410:
		return "ionixnetmon", true
	case 7411:
		return "daqstream", true
	case 7421:
		return "mtportmon", true
	case 7426:
		return "pmdmgr", true
	case 7427:
		return "oveadmgr", true
	case 7428:
		return "ovladmgr", true
	case 7429:
		return "opi-sock", true
	case 7430:
		return "xmpv7", true
	case 7431:
		return "pmd", true
	case 7437:
		return "faximum", true
	case 7443:
		return "oracleas-https", true
	case 7471:
		return "sttunnel", true
	case 7473:
		return "rise", true
	case 7474:
		return "neo4j", true
	case 7478:
		return "openit", true
	case 7491:
		return "telops-lmd", true
	case 7500:
		return "silhouette", true
	case 7501:
		return "ovbus", true
	case 7508:
		return "adcp", true
	case 7509:
		return "acplt", true
	case 7510:
		return "ovhpas", true
	case 7511:
		return "pafec-lm", true
	case 7542:
		return "saratoga", true
	case 7543:
		return "atul", true
	case 7544:
		return "nta-ds", true
	case 7545:
		return "nta-us", true
	case 7546:
		return "cfs", true
	case 7547:
		return "cwmp", true
	case 7548:
		return "tidp", true
	case 7549:
		return "nls-tl", true
	case 7551:
		return "controlone-con", true
	case 7560:
		return "sncp", true
	case 7563:
		return "cfw", true
	case 7566:
		return "vsi-omega", true
	case 7569:
		return "dell-eql-asm", true
	case 7570:
		return "aries-kfinder", true
	case 7574:
		return "coherence", true
	case 7588:
		return "sun-lm", true
	case 7606:
		return "mipi-debug", true
	case 7624:
		return "indi", true
	case 7626:
		return "simco", true
	case 7627:
		return "soap-http", true
	case 7628:
		return "zen-pawn", true
	case 7629:
		return "xdas", true
	case 7630:
		return "hawk", true
	case 7631:
		return "tesla-sys-msg", true
	case 7633:
		return "pmdfmgt", true
	case 7648:
		return "cuseeme", true
	case 7663:
		return "rome", true
	case 7672:
		return "imqstomp", true
	case 7673:
		return "imqstomps", true
	case 7674:
		return "imqtunnels", true
	case 7675:
		return "imqtunnel", true
	case 7676:
		return "imqbrokerd", true
	case 7677:
		return "sun-user-https", true
	case 7680:
		return "ms-do", true
	case 7683:
		return "dmt", true
	case 7687:
		return "bolt", true
	case 7689:
		return "collaber", true
	case 7690:
		return "sovd", true
	case 7697:
		return "klio", true
	case 7700:
		return "em7-secom", true
	case 7707:
		return "sync-em7", true
	case 7708:
		return "scinet", true
	case 7720:
		return "medimageportal", true
	case 7724:
		return "nsdeepfreezectl", true
	case 7725:
		return "nitrogen", true
	case 7726:
		return "freezexservice", true
	case 7727:
		return "trident-data", true
	case 7728:
		return "osvr", true
	case 7734:
		return "smip", true
	case 7738:
		return "aiagent", true
	case 7741:
		return "scriptview", true
	case 7742:
		return "msss", true
	case 7743:
		return "sstp-1", true
	case 7744:
		return "raqmon-pdu", true
	case 7747:
		return "prgp", true
	case 7775:
		return "inetfs", true
	case 7777:
		return "cbt", true
	case 7778:
		return "interwise", true
	case 7779:
		return "vstat", true
	case 7781:
		return "accu-lmgr", true
	case 7786:
		return "minivend", true
	case 7787:
		return "popup-reminders", true
	case 7789:
		return "office-tools", true
	case 7794:
		return "q3ade", true
	case 7797:
		return "pnet-conn", true
	case 7798:
		return "pnet-enc", true
	case 7799:
		return "altbsdp", true
	case 7800:
		return "asr", true
	case 7801:
		return "ssp-client", true
	case 7810:
		return "rbt-wanopt", true
	case 7845:
		return "apc-7845", true
	case 7846:
		return "apc-7846", true
	case 7847:
		return "csoauth", true
	case 7869:
		return "mobileanalyzer", true
	case 7870:
		return "rbt-smc", true
	case 7871:
		return "mdm", true
	case 7878:
		return "owms", true
	case 7880:
		return "pss", true
	case 7887:
		return "ubroker", true
	case 7900:
		return "mevent", true
	case 7901:
		return "tnos-sp", true
	case 7902:
		return "tnos-dp", true
	case 7903:
		return "tnos-dps", true
	case 7913:
		return "qo-secure", true
	case 7932:
		return "t2-drm", true
	case 7933:
		return "t2-brm", true
	case 7962:
		return "generalsync", true
	case 7967:
		return "supercell", true
	case 7979:
		return "micromuse-ncps", true
	case 7980:
		return "quest-vista", true
	case 7981:
		return "sossd-collect", true
	case 7982:
		return "sossd-agent", true
	case 7997:
		return "pushns", true
	case 7999:
		return "irdmi2", true
	case 8000:
		return "irdmi", true
	case 8001:
		return "vcom-tunnel", true
	case 8002:
		return "teradataordbms", true
	case 8003:
		return "mcreport", true
	case 8004:
		return "p2pevolvenet", true
	case 8005:
		return "mxi", true
	case 8006:
		return "wpl-analytics", true
	case 8007:
		return "warppipe", true
	case 8008:
		return "http-alt", true
	case 8009:
		return "nvme-disc", true
	case 8015:
		return "cfg-cloud", true
	case 8016:
		return "ads-s", true
	case 8019:
		return "qbdb", true
	case 8020:
		return "intu-ec-svcdisc", true
	case 8021:
		return "intu-ec-client", true
	case 8022:
		return "oa-system", true
	case 8023:
		return "arca-api", true
	case 8025:
		return "ca-audit-da", true
	case 8026:
		return "ca-audit-ds", true
	case 8027:
		return "papachi-p2p-srv", true
	case 8032:
		return "pro-ed", true
	case 8033:
		return "mindprint", true
	case 8034:
		return "vantronix-mgmt", true
	case 8040:
		return "ampify", true
	case 8041:
		return "enguity-xccetp", true
	case 8042:
		return "fs-agent", true
	case 8043:
		return "fs-server", true
	case 8044:
		return "fs-mgmt", true
	case 8051:
		return "rocrail", true
	case 8052:
		return "senomix01", true
	case 8053:
		return "senomix02", true
	case 8054:
		return "senomix03", true
	case 8055:
		return "senomix04", true
	case 8056:
		return "senomix05", true
	case 8057:
		return "senomix06", true
	case 8058:
		return "senomix07", true
	case 8059:
		return "senomix08", true
	case 8066:
		return "toad-bi-appsrvr", true
	case 8067:
		return "infi-async", true
	case 8070:
		return "ucs-isc", true
	case 8074:
		return "gadugadu", true
	case 8077:
		return "mles", true
	case 8080:
		return "http-alt", true
	case 8081:
		return "sunproxyadmin", true
	case 8082:
		return "us-cli", true
	case 8083:
		return "us-srv", true
	case 8084:
		return "websnp", true
	case 8086:
		return "d-s-n", true
	case 8087:
		return "simplifymedia", true
	case 8088:
		return "radan-http", true
	case 8090:
		return "opsmessaging", true
	case 8091:
		return "jamlink", true
	case 8097:
		return "sac", true
	case 8100:
		return "xprint-server", true
	case 8101:
		return "ldoms-migr", true
	case 8102:
		return "kz-migr", true
	case 8115:
		return "mtl8000-matrix", true
	case 8116:
		return "cp-cluster", true
	case 8117:
		return "purityrpc", true
	case 8118:
		return "privoxy", true
	case 8121:
		return "apollo-data", true
	case 8122:
		return "apollo-admin", true
	case 8128:
		return "paycash-online", true
	case 8129:
		return "paycash-wbp", true
	case 8130:
		return "indigo-vrmi", true
	case 8131:
		return "indigo-vbcp", true
	case 8132:
		return "dbabble", true
	case 8140:
		return "puppet", true
	case 8148:
		return "isdd", true
	case 8153:
		return "quantastor", true
	case 8160:
		return "patrol", true
	case 8161:
		return "patrol-snmp", true
	case 8162:
		return "lpar2rrd", true
	case 8181:
		return "intermapper", true
	case 8182:
		return "vmware-fdm", true
	case 8183:
		return "proremote", true
	case 8184:
		return "itach", true
	case 8190:
		return "gcp-rphy", true
	case 8191:
		return "limnerpressure", true
	case 8192:
		return "spytechphone", true
	case 8194:
		return "blp1", true
	case 8195:
		return "blp2", true
	case 8199:
		return "vvr-data", true
	case 8200:
		return "trivnet1", true
	case 8201:
		return "trivnet2", true
	case 8204:
		return "lm-perfworks", true
	case 8205:
		return "lm-instmgr", true
	case 8206:
		return "lm-dta", true
	case 8207:
		return "lm-sserver", true
	case 8208:
		return "lm-webwatcher", true
	case 8230:
		return "rexecj", true
	case 8243:
		return "synapse-nhttps", true
	case 8270:
		return "robot-remote", true
	case 8276:
		return "ms-mcc", true
	case 8280:
		return "synapse-nhttp", true
	case 8282:
		return "libelle", true
	case 8292:
		return "blp3", true
	case 8293:
		return "hiperscan-id", true
	case 8294:
		return "blp4", true
	case 8300:
		return "tmi", true
	case 8301:
		return "amberon", true
	case 8313:
		return "hub-open-net", true
	case 8320:
		return "tnp-discover", true
	case 8321:
		return "tnp", true
	case 8322:
		return "garmin-marine", true
	case 8351:
		return "server-find", true
	case 8376:
		return "cruise-enum", true
	case 8377:
		return "cruise-swroute", true
	case 8378:
		return "cruise-config", true
	case 8379:
		return "cruise-diags", true
	case 8380:
		return "cruise-update", true
	case 8383:
		return "m2mservices", true
	case 8400:
		return "cvd", true
	case 8401:
		return "sabarsd", true
	case 8402:
		return "abarsd", true
	case 8403:
		return "admind", true
	case 8404:
		return "svcloud", true
	case 8405:
		return "svbackup", true
	case 8415:
		return "dlpx-sp", true
	case 8416:
		return "espeech", true
	case 8417:
		return "espeech-rtp", true
	case 8423:
		return "aritts", true
	case 8432:
		return "pgbackrest", true
	case 8442:
		return "cybro-a-bus", true
	case 8443:
		return "pcsync-https", true
	case 8444:
		return "pcsync-http", true
	case 8445:
		return "copy", true
	case 8450:
		return "npmp", true
	case 8457:
		return "nexentamv", true
	case 8470:
		return "cisco-avp", true
	case 8471:
		return "pim-port", true
	case 8472:
		return "otv", true
	case 8473:
		return "vp2p", true
	case 8474:
		return "noteshare", true
	case 8500:
		return "fmtp", true
	case 8501:
		return "cmtp-mgt", true
	case 8502:
		return "ftnmtp", true
	case 8554:
		return "rtsp-alt", true
	case 8555:
		return "d-fence", true
	case 8567:
		return "dof-tunnel", true
	case 8600:
		return "asterix", true
	case 8610:
		return "canon-mfnp", true
	case 8611:
		return "canon-bjnp1", true
	case 8612:
		return "canon-bjnp2", true
	case 8613:
		return "canon-bjnp3", true
	case 8614:
		return "canon-bjnp4", true
	case 8615:
		return "imink", true
	case 8665:
		return "monetra", true
	case 8666:
		return "monetra-admin", true
	case 8675:
		return "msi-cps-rm", true
	case 8686:
		return "sun-as-jmxrmi", true
	case 8688:
		return "openremote-ctrl", true
	case 8699:
		return "vnyx", true
	case 8710:
		return "semi-grpc", true
	case 8711:
		return "nvc", true
	case 8733:
		return "ibus", true
	case 8750:
		return "dey-keyneg", true
	case 8763:
		return "mc-appserver", true
	case 8764:
		return "openqueue", true
	case 8765:
		return "ultraseek-http", true
	case 8766:
		return "amcs", true
	case 8767:
		return "core-of-source", true
	case 8768:
		return "sandpolis", true
	case 8769:
		return "oktaauthenticat", true
	case 8770:
		return "dpap", true
	case 8778:
		return "uec", true
	case 8786:
		return "msgclnt", true
	case 8787:
		return "msgsrvr", true
	case 8793:
		return "acd-pm", true
	case 8800:
		return "sunwebadmin", true
	case 8804:
		return "truecm", true
	case 8873:
		return "dxspider", true
	case 8880:
		return "cddbp-alt", true
	case 8881:
		return "galaxy4d", true
	case 8883:
		return "secure-mqtt", true
	case 8888:
		return "ddi-tcp-1", true
	case 8889:
		return "ddi-tcp-2", true
	case 8890:
		return "ddi-tcp-3", true
	case 8891:
		return "ddi-tcp-4", true
	case 8892:
		return "ddi-tcp-5", true
	case 8893:
		return "ddi-tcp-6", true
	case 8894:
		return "ddi-tcp-7", true
	case 8899:
		return "ospf-lite", true
	case 8900:
		return "jmb-cds1", true
	case 8901:
		return "jmb-cds2", true
	case 8908:
		return "dpp", true
	case 8910:
		return "manyone-http", true
	case 8911:
		return "manyone-xml", true
	case 8912:
		return "wcbackup", true
	case 8913:
		return "dragonfly", true
	case 8937:
		return "twds", true
	case 8953:
		return "ub-dns-control", true
	case 8954:
		return "cumulus-admin", true
	case 8980:
		return "nod-provider", true
	case 8989:
		return "sunwebadmins", true
	case 8990:
		return "http-wmap", true
	case 8991:
		return "https-wmap", true
	case 8997:
		return "oracle-ms-ens", true
	case 8998:
		return "canto-roboflow", true
	case 8999:
		return "bctp", true
	case 9000:
		return "cslistener", true
	case 9001:
		return "etlservicemgr", true
	case 9002:
		return "dynamid", true
	case 9005:
		return "golem", true
	case 9008:
		return "ogs-server", true
	case 9009:
		return "pichat", true
	case 9010:
		return "sdr", true
	case 9020:
		return "tambora", true
	case 9021:
		return "panagolin-ident", true
	case 9022:
		return "paragent", true
	case 9023:
		return "swa-1", true
	case 9024:
		return "swa-2", true
	case 9025:
		return "swa-3", true
	case 9026:
		return "swa-4", true
	case 9050:
		return "versiera", true
	case 9051:
		return "fio-cmgmt", true
	case 9060:
		return "CardWeb-IO", true
	case 9080:
		return "glrpc", true
	case 9083:
		return "emc-pp-mgmtsvc", true
	case 9084:
		return "aurora", true
	case 9085:
		return "ibm-rsyscon", true
	case 9086:
		return "net2display", true
	case 9087:
		return "classic", true
	case 9088:
		return "sqlexec", true
	case 9089:
		return "sqlexec-ssl", true
	case 9090:
		return "websm", true
	case 9091:
		return "xmltec-xmlmail", true
	case 9092:
		return "XmlIpcRegSvc", true
	case 9093:
		return "copycat", true
	case 9100:
		return "hp-pdl-datastr", true
	case 9101:
		return "bacula-dir", true
	case 9102:
		return "bacula-fd", true
	case 9103:
		return "bacula-sd", true
	case 9104:
		return "peerwire", true
	case 9105:
		return "xadmin", true
	case 9106:
		return "astergate", true
	case 9107:
		return "astergatefax", true
	case 9111:
		return "hexxorecore", true
	case 9119:
		return "mxit", true
	case 9122:
		return "grcmp", true
	case 9123:
		return "grcp", true
	case 9131:
		return "dddp", true
	case 9160:
		return "apani1", true
	case 9161:
		return "apani2", true
	case 9162:
		return "apani3", true
	case 9163:
		return "apani4", true
	case 9164:
		return "apani5", true
	case 9191:
		return "sun-as-jpda", true
	case 9200:
		return "wap-wsp", true
	case 9201:
		return "wap-wsp-wtp", true
	case 9202:
		return "wap-wsp-s", true
	case 9203:
		return "wap-wsp-wtp-s", true
	case 9204:
		return "wap-vcard", true
	case 9205:
		return "wap-vcal", true
	case 9206:
		return "wap-vcard-s", true
	case 9207:
		return "wap-vcal-s", true
	case 9208:
		return "rjcdb-vcards", true
	case 9209:
		return "almobile-system", true
	case 9210:
		return "oma-mlp", true
	case 9211:
		return "oma-mlp-s", true
	case 9212:
		return "serverviewdbms", true
	case 9213:
		return "serverstart", true
	case 9214:
		return "ipdcesgbs", true
	case 9215:
		return "insis", true
	case 9216:
		return "acme", true
	case 9217:
		return "fsc-port", true
	case 9222:
		return "teamcoherence", true
	case 9255:
		return "mon", true
	case 9278:
		return "pegasus", true
	case 9279:
		return "pegasus-ctl", true
	case 9280:
		return "pgps", true
	case 9281:
		return "swtp-port1", true
	case 9282:
		return "swtp-port2", true
	case 9283:
		return "callwaveiam", true
	case 9284:
		return "visd", true
	case 9285:
		return "n2h2server", true
	case 9287:
		return "cumulus", true
	case 9292:
		return "armtechdaemon", true
	case 9293:
		return "storview", true
	case 9294:
		return "armcenterhttp", true
	case 9295:
		return "armcenterhttps", true
	case 9300:
		return "vrace", true
	case 9306:
		return "sphinxql", true
	case 9310:
		return "sapms", true
	case 9312:
		return "sphinxapi", true
	case 9318:
		return "secure-ts", true
	case 9321:
		return "guibase", true
	case 9339:
		return "gnmi-gnoi", true
	case 9340:
		return "gribi", true
	case 9343:
		return "mpidcmgr", true
	case 9344:
		return "mphlpdmc", true
	case 9345:
		return "rancher", true
	case 9346:
		return "ctechlicensing", true
	case 9374:
		return "fjdmimgr", true
	case 9380:
		return "boxp", true
	case 9387:
		return "d2dconfig", true
	case 9388:
		return "d2ddatatrans", true
	case 9389:
		return "adws", true
	case 9390:
		return "otp", true
	case 9396:
		return "fjinvmgr", true
	case 9397:
		return "mpidcagt", true
	case 9400:
		return "sec-t4net-srv", true
	case 9401:
		return "sec-t4net-clt", true
	case 9402:
		return "sec-pc2fax-srv", true
	case 9418:
		return "git", true
	case 9443:
		return "tungsten-https", true
	case 9444:
		return "wso2esb-console", true
	case 9445:
		return "mindarray-ca", true
	case 9450:
		return "sntlkeyssrvr", true
	case 9500:
		return "ismserver", true
	case 9535:
		return "mngsuite", true
	case 9536:
		return "laes-bf", true
	case 9555:
		return "trispen-sra", true
	case 9559:
		return "p4runtime", true
	case 9592:
		return "ldgateway", true
	case 9593:
		return "cba8", true
	case 9594:
		return "msgsys", true
	case 9595:
		return "pds", true
	case 9596:
		return "mercury-disc", true
	case 9597:
		return "pd-admin", true
	case 9598:
		return "vscp", true
	case 9599:
		return "robix", true
	case 9600:
		return "micromuse-ncpw", true
	case 9612:
		return "streamcomm-ds", true
	case 9614:
		return "iadt-tls", true
	case 9616:
		return "erunbook-agent", true
	case 9617:
		return "erunbook-server", true
	case 9618:
		return "condor", true
	case 9628:
		return "odbcpathway", true
	case 9629:
		return "uniport", true
	case 9630:
		return "peoctlr", true
	case 9631:
		return "peocoll", true
	case 9640:
		return "pqsflows", true
	case 9666:
		return "zoomcp", true
	case 9667:
		return "xmms2", true
	case 9668:
		return "tec5-sdctp", true
	case 9694:
		return "client-wakeup", true
	case 9695:
		return "ccnx", true
	case 9700:
		return "board-roar", true
	case 9747:
		return "l5nas-parchan", true
	case 9750:
		return "board-voip", true
	case 9753:
		return "rasadv", true
	case 9762:
		return "tungsten-http", true
	case 9800:
		return "davsrc", true
	case 9801:
		return "sstp-2", true
	case 9802:
		return "davsrcs", true
	case 9875:
		return "sapv1", true
	case 9876:
		return "sd", true
	case 9877:
		return "x510", true
	case 9888:
		return "cyborg-systems", true
	case 9889:
		return "gt-proxy", true
	case 9898:
		return "monkeycom", true
	case 9900:
		return "iua", true
	case 9909:
		return "domaintime", true
	case 9911:
		return "sype-transport", true
	case 9925:
		return "xybrid-cloud", true
	case 9950:
		return "apc-9950", true
	case 9951:
		return "apc-9951", true
	case 9952:
		return "apc-9952", true
	case 9953:
		return "acis", true
	case 9954:
		return "hinp", true
	case 9955:
		return "alljoyn-stm", true
	case 9966:
		return "odnsp", true
	case 9978:
		return "xybrid-rt", true
	case 9979:
		return "visweather", true
	case 9981:
		return "pumpkindb", true
	case 9987:
		return "dsm-scm-target", true
	case 9988:
		return "nsesrvr", true
	case 9990:
		return "osm-appsrvr", true
	case 9991:
		return "osm-oev", true
	case 9992:
		return "palace-1", true
	case 9993:
		return "palace-2", true
	case 9994:
		return "palace-3", true
	case 9995:
		return "palace-4", true
	case 9996:
		return "palace-5", true
	case 9997:
		return "palace-6", true
	case 9998:
		return "distinct32", true
	case 9999:
		return "distinct", true
	case 10000:
		return "ndmp", true
	case 10001:
		return "scp-config", true
	case 10002:
		return "documentum", true
	case 10003:
		return "documentum-s", true
	case 10004:
		return "emcrmirccd", true
	case 10005:
		return "emcrmird", true
	case 10006:
		return "netapp-sync", true
	case 10007:
		return "mvs-capacity", true
	case 10008:
		return "octopus", true
	case 10009:
		return "swdtp-sv", true
	case 10010:
		return "rxapi", true
	case 10020:
		return "abb-hw", true
	case 10050:
		return "zabbix-agent", true
	case 10051:
		return "zabbix-trapper", true
	case 10055:
		return "qptlmd", true
	case 10080:
		return "amanda", true
	case 10081:
		return "famdc", true
	case 10100:
		return "itap-ddtp", true
	case 10101:
		return "ezmeeting-2", true
	case 10102:
		return "ezproxy-2", true
	case 10103:
		return "ezrelay", true
	case 10104:
		return "swdtp", true
	case 10107:
		return "bctp-server", true
	case 10110:
		return "nmea-0183", true
	case 10113:
		return "netiq-endpoint", true
	case 10114:
		return "netiq-qcheck", true
	case 10115:
		return "netiq-endpt", true
	case 10116:
		return "netiq-voipa", true
	case 10117:
		return "iqrm", true
	case 10125:
		return "cimple", true
	case 10128:
		return "bmc-perf-sd", true
	case 10129:
		return "bmc-gms", true
	case 10160:
		return "qb-db-server", true
	case 10161:
		return "snmptls", true
	case 10162:
		return "snmptls-trap", true
	case 10200:
		return "trisoap", true
	case 10201:
		return "rsms", true
	case 10252:
		return "apollo-relay", true
	case 10260:
		return "axis-wimp-port", true
	case 10261:
		return "tile-ml", true
	case 10288:
		return "blocks", true
	case 10321:
		return "cosir", true
	case 10443:
		return "cirrossp", true
	case 10540:
		return "MOS-lower", true
	case 10541:
		return "MOS-upper", true
	case 10542:
		return "MOS-aux", true
	case 10543:
		return "MOS-soap", true
	case 10544:
		return "MOS-soap-opt", true
	case 10548:
		return "serverdocs", true
	case 10631:
		return "printopia", true
	case 10800:
		return "gap", true
	case 10805:
		return "lpdg", true
	case 10809:
		return "nbd", true
	case 10860:
		return "helix", true
	case 10880:
		return "bveapi", true
	case 10933:
		return "octopustentacle", true
	case 10990:
		return "rmiaux", true
	case 11000:
		return "irisa", true
	case 11001:
		return "metasys", true
	case 11095:
		return "weave", true
	case 11103:
		return "origo-sync", true
	case 11104:
		return "netapp-icmgmt", true
	case 11105:
		return "netapp-icdata", true
	case 11106:
		return "sgi-lk", true
	case 11109:
		return "sgi-dmfmgr", true
	case 11110:
		return "sgi-soap", true
	case 11111:
		return "vce", true
	case 11112:
		return "dicom", true
	case 11161:
		return "suncacao-snmp", true
	case 11162:
		return "suncacao-jmxmp", true
	case 11163:
		return "suncacao-rmi", true
	case 11164:
		return "suncacao-csa", true
	case 11165:
		return "suncacao-websvc", true
	case 11172:
		return "oemcacao-jmxmp", true
	case 11173:
		return "t5-straton", true
	case 11174:
		return "oemcacao-rmi", true
	case 11175:
		return "oemcacao-websvc", true
	case 11201:
		return "smsqp", true
	case 11202:
		return "dcsl-backup", true
	case 11208:
		return "wifree", true
	case 11211:
		return "memcache", true
	case 11235:
		return "xcompute", true
	case 11319:
		return "imip", true
	case 11320:
		return "imip-channels", true
	case 11321:
		return "arena-server", true
	case 11367:
		return "atm-uhas", true
	case 11371:
		return "hkp", true
	case 11489:
		return "asgcypresstcps", true
	case 11600:
		return "tempest-port", true
	case 11623:
		return "emc-xsw-dconfig", true
	case 11720:
		return "h323callsigalt", true
	case 11723:
		return "emc-xsw-dcache", true
	case 11751:
		return "intrepid-ssl", true
	case 11796:
		return "lanschool", true
	case 11876:
		return "xoraya", true
	case 11967:
		return "sysinfo-sp", true
	case 11971:
		return "tibsd", true
	case 12000:
		return "entextxid", true
	case 12001:
		return "entextnetwk", true
	case 12002:
		return "entexthigh", true
	case 12003:
		return "entextmed", true
	case 12004:
		return "entextlow", true
	case 12005:
		return "dbisamserver1", true
	case 12006:
		return "dbisamserver2", true
	case 12007:
		return "accuracer", true
	case 12008:
		return "accuracer-dbms", true
	case 12010:
		return "edbsrvr", true
	case 12012:
		return "vipera", true
	case 12013:
		return "vipera-ssl", true
	case 12109:
		return "rets-ssl", true
	case 12121:
		return "nupaper-ss", true
	case 12168:
		return "cawas", true
	case 12172:
		return "hivep", true
	case 12300:
		return "linogridengine", true
	case 12302:
		return "rads", true
	case 12321:
		return "warehouse-sss", true
	case 12322:
		return "warehouse", true
	case 12345:
		return "italk", true
	case 12546:
		return "carb-repl-ctrl", true
	case 12753:
		return "tsaf", true
	case 12865:
		return "netperf", true
	case 13160:
		return "i-zipqd", true
	case 13216:
		return "bcslogc", true
	case 13217:
		return "rs-pias", true
	case 13218:
		return "emc-vcas-tcp", true
	case 13223:
		return "powwow-client", true
	case 13224:
		return "powwow-server", true
	case 13400:
		return "doip-data", true
	case 13720:
		return "bprd", true
	case 13721:
		return "bpdbm", true
	case 13722:
		return "bpjava-msvc", true
	case 13724:
		return "vnetd", true
	case 13782:
		return "bpcd", true
	case 13783:
		return "vopied", true
	case 13785:
		return "nbdb", true
	case 13786:
		return "nomdb", true
	case 13818:
		return "dsmcc-config", true
	case 13819:
		return "dsmcc-session", true
	case 13820:
		return "dsmcc-passthru", true
	case 13821:
		return "dsmcc-download", true
	case 13822:
		return "dsmcc-ccp", true
	case 13823:
		return "bmdss", true
	case 13832:
		return "a-trust-rpc", true
	case 13894:
		return "ucontrol", true
	case 13929:
		return "dta-systems", true
	case 13930:
		return "medevolve", true
	case 14000:
		return "scotty-ft", true
	case 14001:
		return "sua", true
	case 14033:
		return "sage-best-com1", true
	case 14034:
		return "sage-best-com2", true
	case 14141:
		return "vcs-app", true
	case 14142:
		return "icpp", true
	case 14143:
		return "icpps", true
	case 14145:
		return "gcm-app", true
	case 14149:
		return "vrts-tdd", true
	case 14150:
		return "vcscmd", true
	case 14154:
		return "vad", true
	case 14250:
		return "cps", true
	case 14414:
		return "ca-web-update", true
	case 14500:
		return "xpra", true
	case 14936:
		return "hde-lcesrvr-1", true
	case 14937:
		return "hde-lcesrvr-2", true
	case 15000:
		return "hydap", true
	case 15002:
		return "onep-tls", true
	case 15345:
		return "xpilot", true
	case 15363:
		return "3link", true
	case 15555:
		return "cisco-snat", true
	case 15660:
		return "bex-xr", true
	case 15740:
		return "ptp", true
	case 15999:
		return "programmar", true
	case 16000:
		return "fmsas", true
	case 16001:
		return "fmsascon", true
	case 16002:
		return "gsms", true
	case 16020:
		return "jwpc", true
	case 16021:
		return "jwpc-bin", true
	case 16161:
		return "sun-sea-port", true
	case 16162:
		return "solaris-audit", true
	case 16309:
		return "etb4j", true
	case 16310:
		return "pduncs", true
	case 16311:
		return "pdefmns", true
	case 16360:
		return "netserialext1", true
	case 16361:
		return "netserialext2", true
	case 16367:
		return "netserialext3", true
	case 16368:
		return "netserialext4", true
	case 16384:
		return "connected", true
	case 16385:
		return "rdgs", true
	case 16619:
		return "xoms", true
	case 16665:
		return "axon-tunnel", true
	case 16789:
		return "cadsisvr", true
	case 16900:
		return "newbay-snc-mc", true
	case 16950:
		return "sgcip", true
	case 16991:
		return "intel-rci-mp", true
	case 16992:
		return "amt-soap-http", true
	case 16993:
		return "amt-soap-https", true
	case 16994:
		return "amt-redir-tcp", true
	case 16995:
		return "amt-redir-tls", true
	case 17007:
		return "isode-dua", true
	case 17010:
		return "ncpu", true
	case 17184:
		return "vestasdlp", true
	case 17185:
		return "soundsvirtual", true
	case 17219:
		return "chipper", true
	case 17220:
		return "avtp", true
	case 17221:
		return "avdecc", true
	case 17223:
		return "isa100-gci", true
	case 17225:
		return "trdp-md", true
	case 17234:
		return "integrius-stp", true
	case 17235:
		return "ssh-mgmt", true
	case 17500:
		return "db-lsp", true
	case 17555:
		return "ailith", true
	case 17729:
		return "ea", true
	case 17754:
		return "zep", true
	case 17755:
		return "zigbee-ip", true
	case 17756:
		return "zigbee-ips", true
	case 17777:
		return "sw-orion", true
	case 18000:
		return "biimenu", true
	case 18104:
		return "radpdf", true
	case 18136:
		return "racf", true
	case 18181:
		return "opsec-cvp", true
	case 18182:
		return "opsec-ufp", true
	case 18183:
		return "opsec-sam", true
	case 18184:
		return "opsec-lea", true
	case 18185:
		return "opsec-omi", true
	case 18186:
		return "ohsc", true
	case 18187:
		return "opsec-ela", true
	case 18241:
		return "checkpoint-rtm", true
	case 18242:
		return "iclid", true
	case 18243:
		return "clusterxl", true
	case 18262:
		return "gv-pf", true
	case 18463:
		return "ac-cluster", true
	case 18634:
		return "rds-ib", true
	case 18635:
		return "rds-ip", true
	case 18668:
		return "vdmmesh", true
	case 18769:
		return "ique", true
	case 18881:
		return "infotos", true
	case 18888:
		return "apc-necmp", true
	case 19000:
		return "igrid", true
	case 19007:
		return "scintilla", true
	case 19020:
		return "j-link", true
	case 19191:
		return "opsec-uaa", true
	case 19194:
		return "ua-secureagent", true
	case 19220:
		return "cora", true
	case 19283:
		return "keysrvr", true
	case 19315:
		return "keyshadow", true
	case 19398:
		return "mtrgtrans", true
	case 19410:
		return "hp-sco", true
	case 19411:
		return "hp-sca", true
	case 19412:
		return "hp-sessmon", true
	case 19539:
		return "fxuptp", true
	case 19540:
		return "sxuptp", true
	case 19541:
		return "jcp", true
	case 19790:
		return "faircom-db", true
	case 19998:
		return "iec-104-sec", true
	case 19999:
		return "dnp-sec", true
	case 20000:
		return "dnp", true
	case 20001:
		return "microsan", true
	case 20002:
		return "commtact-http", true
	case 20003:
		return "commtact-https", true
	case 20005:
		return "openwebnet", true
	case 20013:
		return "ss-idi", true
	case 20014:
		return "opendeploy", true
	case 20034:
		return "nburn-id", true
	case 20046:
		return "tmophl7mts", true
	case 20048:
		return "mountd", true
	case 20049:
		return "nfsrdma", true
	case 20057:
		return "avesterra", true
	case 20167:
		return "tolfab", true
	case 20202:
		return "ipdtp-port", true
	case 20222:
		return "ipulse-ics", true
	case 20480:
		return "emwavemsg", true
	case 20670:
		return "track", true
	case 20810:
		return "crtech-nlm", true
	case 20999:
		return "athand-mmp", true
	case 21000:
		return "irtrans", true
	case 21010:
		return "notezilla-lan", true
	case 21212:
		return "trinket-agent", true
	case 21213:
		return "cohesity-agent", true
	case 21221:
		return "aigairserver", true
	case 21553:
		return "rdm-tfs", true
	case 21554:
		return "dfserver", true
	case 21590:
		return "vofr-gateway", true
	case 21800:
		return "tvpm", true
	case 21801:
		return "sal", true
	case 21845:
		return "webphone", true
	case 21846:
		return "netspeak-is", true
	case 21847:
		return "netspeak-cs", true
	case 21848:
		return "netspeak-acd", true
	case 21849:
		return "netspeak-cps", true
	case 22000:
		return "snapenetio", true
	case 22001:
		return "optocontrol", true
	case 22002:
		return "optohost002", true
	case 22003:
		return "optohost003", true
	case 22004:
		return "optohost004", true
	case 22005:
		return "optohost004", true
	case 22125:
		return "dcap", true
	case 22128:
		return "gsidcap", true
	case 22222:
		return "easyengine", true
	case 22273:
		return "wnn6", true
	case 22305:
		return "cis", true
	case 22333:
		return "showcockpit-net", true
	case 22335:
		return "shrewd-control", true
	case 22343:
		return "cis-secure", true
	case 22347:
		return "wibukey", true
	case 22350:
		return "codemeter", true
	case 22351:
		return "codemeter-cmwan", true
	case 22537:
		return "caldsoft-backup", true
	case 22555:
		return "vocaltec-wconf", true
	case 22763:
		return "talikaserver", true
	case 22800:
		return "aws-brf", true
	case 22951:
		return "brf-gw", true
	case 23000:
		return "inovaport1", true
	case 23001:
		return "inovaport2", true
	case 23002:
		return "inovaport3", true
	case 23003:
		return "inovaport4", true
	case 23004:
		return "inovaport5", true
	case 23005:
		return "inovaport6", true
	case 23053:
		return "gntp", true
	case 23294:
		return "5afe-dir", true
	case 23333:
		return "elxmgmt", true
	case 23400:
		return "novar-dbase", true
	case 23401:
		return "novar-alarm", true
	case 23402:
		return "novar-global", true
	case 23456:
		return "aequus", true
	case 23457:
		return "aequus-alt", true
	case 23546:
		return "areaguard-neo", true
	case 24000:
		return "med-ltp", true
	case 24001:
		return "med-fsp-rx", true
	case 24002:
		return "med-fsp-tx", true
	case 24003:
		return "med-supp", true
	case 24004:
		return "med-ovw", true
	case 24005:
		return "med-ci", true
	case 24006:
		return "med-net-svc", true
	case 24242:
		return "filesphere", true
	case 24249:
		return "vista-4gl", true
	case 24321:
		return "ild", true
	case 24323:
		return "vrmg-ip", true
	case 24386:
		return "intel-rci", true
	case 24465:
		return "tonidods", true
	case 24554:
		return "binkp", true
	case 24577:
		return "bilobit", true
	case 24666:
		return "sdtvwcam", true
	case 24676:
		return "canditv", true
	case 24677:
		return "flashfiler", true
	case 24678:
		return "proactivate", true
	case 24680:
		return "tcc-http", true
	case 24754:
		return "cslg", true
	case 24922:
		return "find", true
	case 25000:
		return "icl-twobase1", true
	case 25001:
		return "icl-twobase2", true
	case 25002:
		return "icl-twobase3", true
	case 25003:
		return "icl-twobase4", true
	case 25004:
		return "icl-twobase5", true
	case 25005:
		return "icl-twobase6", true
	case 25006:
		return "icl-twobase7", true
	case 25007:
		return "icl-twobase8", true
	case 25008:
		return "icl-twobase9", true
	case 25009:
		return "icl-twobase10", true
	case 25576:
		return "sauterdongle", true
	case 25604:
		return "idtp", true
	case 25793:
		return "vocaltec-hos", true
	case 25900:
		return "tasp-net", true
	case 25901:
		return "niobserver", true
	case 25902:
		return "nilinkanalyst", true
	case 25903:
		return "niprobe", true
	case 26000:
		return "quake", true
	case 26133:
		return "scscp", true
	case 26208:
		return "wnn6-ds", true
	case 26257:
		return "cockroach", true
	case 26260:
		return "ezproxy", true
	case 26261:
		return "ezmeeting", true
	case 26262:
		return "k3software-svr", true
	case 26263:
		return "k3software-cli", true
	case 26486:
		return "exoline-tcp", true
	case 26487:
		return "exoconfig", true
	case 26489:
		return "exonet", true
	case 27010:
		return "flex-lmadmin", true
	case 27017:
		return "mongodb", true
	case 27345:
		return "imagepump", true
	case 27442:
		return "jesmsjc", true
	case 27504:
		return "kopek-httphead", true
	case 27782:
		return "ars-vista", true
	case 27876:
		return "astrolink", true
	case 27999:
		return "tw-auth-key", true
	case 28000:
		return "nxlmd", true
	case 28001:
		return "pqsp", true
	case 28010:
		return "gruber-cashreg", true
	case 28080:
		return "thor-engine", true
	case 28200:
		return "voxelstorm", true
	case 28240:
		return "siemensgsm", true
	case 28589:
		return "bosswave", true
	case 29000:
		return "saltd-licensing", true
	case 29167:
		return "otmp", true
	case 29999:
		return "bingbang", true
	case 30000:
		return "ndmps", true
	case 30001:
		return "pago-services1", true
	case 30002:
		return "pago-services2", true
	case 30003:
		return "amicon-fpsu-ra", true
	case 30100:
		return "rwp", true
	case 30260:
		return "kingdomsonline", true
	case 30400:
		return "gs-realtime", true
	case 30999:
		return "ovobs", true
	case 31016:
		return "ka-sddp", true
	case 31020:
		return "autotrac-acp", true
	case 31337:
		return "eldim", true
	case 31400:
		return "pace-licensed", true
	case 31416:
		return "xqosd", true
	case 31457:
		return "tetrinet", true
	case 31620:
		return "lm-mon", true
	case 31685:
		return "dsx-monitor", true
	case 31765:
		return "gamesmith-port", true
	case 31948:
		return "iceedcp-tx", true
	case 31949:
		return "iceedcp-rx", true
	case 32034:
		return "iracinghelper", true
	case 32249:
		return "t1distproc60", true
	case 32400:
		return "plex", true
	case 32483:
		return "apm-link", true
	case 32635:
		return "sec-ntb-clnt", true
	case 32636:
		return "DMExpress", true
	case 32767:
		return "filenet-powsrm", true
	case 32768:
		return "filenet-tms", true
	case 32769:
		return "filenet-rpc", true
	case 32770:
		return "filenet-nch", true
	case 32771:
		return "filenet-rmi", true
	case 32772:
		return "filenet-pa", true
	case 32773:
		return "filenet-cm", true
	case 32774:
		return "filenet-re", true
	case 32775:
		return "filenet-pch", true
	case 32776:
		return "filenet-peior", true
	case 32777:
		return "filenet-obrok", true
	case 32801:
		return "mlsn", true
	case 32811:
		return "retp", true
	case 32896:
		return "idmgratm", true
	case 33000:
		return "wg-endpt-comms", true
	case 33060:
		return "mysqlx", true
	case 33123:
		return "aurora-balaena", true
	case 33331:
		return "diamondport", true
	case 33333:
		return "dgi-serv", true
	case 33334:
		return "speedtrace", true
	case 33434:
		return "traceroute", true
	case 33656:
		return "snip-slave", true
	case 33890:
		return "digilent-adept", true
	case 34249:
		return "turbonote-2", true
	case 34378:
		return "p-net-local", true
	case 34379:
		return "p-net-remote", true
	case 34567:
		return "dhanalakshmi", true
	case 34962:
		return "profinet-rt", true
	case 34963:
		return "profinet-rtm", true
	case 34964:
		return "profinet-cm", true
	case 34980:
		return "ethercat", true
	case 35000:
		return "heathview", true
	case 35001:
		return "rt-viewer", true
	case 35002:
		return "rt-sound", true
	case 35003:
		return "rt-devicemapper", true
	case 35004:
		return "rt-classmanager", true
	case 35005:
		return "rt-labtracker", true
	case 35006:
		return "rt-helper", true
	case 35100:
		return "axio-disc", true
	case 35354:
		return "kitim", true
	case 35355:
		return "altova-lm", true
	case 35356:
		return "guttersnex", true
	case 35357:
		return "openstack-id", true
	case 36001:
		return "allpeers", true
	case 36524:
		return "febooti-aw", true
	case 36602:
		return "observium-agent", true
	case 36700:
		return "mapx", true
	case 36865:
		return "kastenxpipe", true
	case 37475:
		return "neckar", true
	case 37483:
		return "gdrive-sync", true
	case 37601:
		return "eftp", true
	case 37654:
		return "unisys-eportal", true
	case 38000:
		return "ivs-database", true
	case 38001:
		return "ivs-insertion", true
	case 38002:
		return "cresco-control", true
	case 38201:
		return "galaxy7-data", true
	case 38202:
		return "fairview", true
	case 38203:
		return "agpolicy", true
	case 38638:
		return "psqlmws", true
	case 38800:
		return "sruth", true
	case 38865:
		return "secrmmsafecopya", true
	case 39063:
		return "vroa", true
	case 39681:
		return "turbonote-1", true
	case 40000:
		return "safetynetp", true
	case 40404:
		return "sptx", true
	case 40841:
		return "cscp", true
	case 40842:
		return "csccredir", true
	case 40843:
		return "csccfirewall", true
	case 41111:
		return "fs-qos", true
	case 41121:
		return "tentacle", true
	case 41230:
		return "z-wave-s", true
	case 41794:
		return "crestron-cip", true
	case 41795:
		return "crestron-ctp", true
	case 41796:
		return "crestron-cips", true
	case 41797:
		return "crestron-ctps", true
	case 42508:
		return "candp", true
	case 42509:
		return "candrp", true
	case 42510:
		return "caerpc", true
	case 42999:
		return "curiosity", true
	case 43000:
		return "recvr-rc", true
	case 43188:
		return "reachout", true
	case 43189:
		return "ndm-agent-port", true
	case 43190:
		return "ip-provision", true
	case 43191:
		return "noit-transport", true
	case 43210:
		return "shaperai", true
	case 43439:
		return "eq3-update", true
	case 43440:
		return "ew-mgmt", true
	case 43441:
		return "ciscocsdb", true
	case 44123:
		return "z-wave-tunnel", true
	case 44321:
		return "pmcd", true
	case 44322:
		return "pmcdproxy", true
	case 44323:
		return "pmwebapi", true
	case 44444:
		return "cognex-dataman", true
	case 44445:
		return "acronis-backup", true
	case 44553:
		return "rbr-debug", true
	case 44818:
		return "EtherNet-IP-2", true
	case 44900:
		return "m3da", true
	case 45000:
		return "asmp", true
	case 45001:
		return "asmps", true
	case 45002:
		return "rs-status", true
	case 45045:
		return "synctest", true
	case 45054:
		return "invision-ag", true
	case 45514:
		return "cloudcheck", true
	case 45678:
		return "eba", true
	case 45824:
		return "dai-shell", true
	case 45825:
		return "qdb2service", true
	case 45966:
		return "ssr-servermgr", true
	case 46336:
		return "inedo", true
	case 46998:
		return "spremotetablet", true
	case 46999:
		return "mediabox", true
	case 47000:
		return "mbus", true
	case 47001:
		return "winrm", true
	case 47557:
		return "dbbrowse", true
	case 47624:
		return "directplaysrvr", true
	case 47806:
		return "ap", true
	case 47808:
		return "bacnet", true
	case 48000:
		return "nimcontroller", true
	case 48001:
		return "nimspooler", true
	case 48002:
		return "nimhub", true
	case 48003:
		return "nimgtw", true
	case 48004:
		return "nimbusdb", true
	case 48005:
		return "nimbusdbctrl", true
	case 48048:
		return "juka", true
	case 48049:
		return "3gpp-cbsp", true
	case 48050:
		return "weandsf", true
	case 48128:
		return "isnetserv", true
	case 48129:
		return "blp5", true
	case 48556:
		return "com-bardac-dw", true
	case 48619:
		return "iqobject", true
	case 48653:
		return "robotraconteur", true
	case 49000:
		return "matahari", true
	case 49001:
		return "nusrp", true
	case 49150:
		return "inspider", true

	}

	return "", false
}

// UDPPortNames contains the port names for all UDP ports.
func UDPPortNames(port UDPPort) (string, bool) {
	switch port {
	case 1:
		return "tcpmux", true
	case 2:
		return "compressnet", true
	case 3:
		return "compressnet", true
	case 5:
		return "rje", true
	case 7:
		return "echo", true
	case 9:
		return "discard", true
	case 11:
		return "systat", true
	case 13:
		return "daytime", true
	case 17:
		return "qotd", true
	case 18:
		return "msp", true
	case 19:
		return "chargen", true
	case 20:
		return "ftp-data", true
	case 21:
		return "ftp", true
	case 22:
		return "ssh", true
	case 23:
		return "telnet", true
	case 25:
		return "smtp", true
	case 27:
		return "nsw-fe", true
	case 29:
		return "msg-icp", true
	case 31:
		return "msg-auth", true
	case 33:
		return "dsp", true
	case 37:
		return "time", true
	case 38:
		return "rap", true
	case 39:
		return "rlp", true
	case 41:
		return "graphics", true
	case 42:
		return "name", true
	case 43:
		return "nicname", true
	case 44:
		return "mpm-flags", true
	case 45:
		return "mpm", true
	case 46:
		return "mpm-snd", true
	case 48:
		return "auditd", true
	case 49:
		return "tacacs", true
	case 50:
		return "re-mail-ck", true
	case 52:
		return "xns-time", true
	case 53:
		return "domain", true
	case 54:
		return "xns-ch", true
	case 55:
		return "isi-gl", true
	case 56:
		return "xns-auth", true
	case 58:
		return "xns-mail", true
	case 62:
		return "acas", true
	case 63:
		return "whoispp", true
	case 64:
		return "covia", true
	case 65:
		return "tacacs-ds", true
	case 66:
		return "sql-net", true
	case 67:
		return "bootps", true
	case 68:
		return "bootpc", true
	case 69:
		return "tftp", true
	case 70:
		return "gopher", true
	case 71:
		return "netrjs-1", true
	case 72:
		return "netrjs-2", true
	case 73:
		return "netrjs-3", true
	case 74:
		return "netrjs-4", true
	case 76:
		return "deos", true
	case 78:
		return "vettcp", true
	case 79:
		return "finger", true
	case 80:
		return "http", true
	case 82:
		return "xfer", true
	case 83:
		return "mit-ml-dev", true
	case 84:
		return "ctf", true
	case 85:
		return "mit-ml-dev", true
	case 86:
		return "mfcobol", true
	case 88:
		return "kerberos", true
	case 89:
		return "su-mit-tg", true
	case 90:
		return "dnsix", true
	case 91:
		return "mit-dov", true
	case 92:
		return "npp", true
	case 93:
		return "dcp", true
	case 94:
		return "objcall", true
	case 95:
		return "supdup", true
	case 96:
		return "dixie", true
	case 97:
		return "swift-rvf", true
	case 98:
		return "tacnews", true
	case 99:
		return "metagram", true
	case 101:
		return "hostname", true
	case 102:
		return "iso-tsap", true
	case 103:
		return "gppitnp", true
	case 104:
		return "acr-nema", true
	case 105:
		return "cso", true
	case 106:
		return "3com-tsmux", true
	case 107:
		return "rtelnet", true
	case 108:
		return "snagas", true
	case 109:
		return "pop2", true
	case 110:
		return "pop3", true
	case 111:
		return "sunrpc", true
	case 112:
		return "mcidas", true
	case 113:
		return "auth", true
	case 115:
		return "sftp", true
	case 116:
		return "ansanotify", true
	case 117:
		return "uucp-path", true
	case 118:
		return "sqlserv", true
	case 119:
		return "nntp", true
	case 120:
		return "cfdptkt", true
	case 121:
		return "erpc", true
	case 122:
		return "smakynet", true
	case 123:
		return "ntp", true
	case 124:
		return "ansatrader", true
	case 125:
		return "locus-map", true
	case 126:
		return "nxedit", true
	case 127:
		return "locus-con", true
	case 128:
		return "gss-xlicen", true
	case 129:
		return "pwdgen", true
	case 130:
		return "cisco-fna", true
	case 131:
		return "cisco-tna", true
	case 132:
		return "cisco-sys", true
	case 133:
		return "statsrv", true
	case 134:
		return "ingres-net", true
	case 135:
		return "epmap", true
	case 136:
		return "profile", true
	case 137:
		return "netbios-ns", true
	case 138:
		return "netbios-dgm", true
	case 139:
		return "netbios-ssn", true
	case 140:
		return "emfis-data", true
	case 141:
		return "emfis-cntl", true
	case 142:
		return "bl-idm", true
	case 144:
		return "uma", true
	case 145:
		return "uaac", true
	case 146:
		return "iso-tp0", true
	case 147:
		return "iso-ip", true
	case 148:
		return "jargon", true
	case 149:
		return "aed-512", true
	case 150:
		return "sql-net", true
	case 151:
		return "hems", true
	case 152:
		return "bftp", true
	case 153:
		return "sgmp", true
	case 154:
		return "netsc-prod", true
	case 155:
		return "netsc-dev", true
	case 156:
		return "sqlsrv", true
	case 157:
		return "knet-cmp", true
	case 158:
		return "pcmail-srv", true
	case 159:
		return "nss-routing", true
	case 160:
		return "sgmp-traps", true
	case 161:
		return "snmp", true
	case 162:
		return "snmptrap", true
	case 163:
		return "cmip-man", true
	case 164:
		return "cmip-agent", true
	case 165:
		return "xns-courier", true
	case 166:
		return "s-net", true
	case 167:
		return "namp", true
	case 168:
		return "rsvd", true
	case 169:
		return "send", true
	case 170:
		return "print-srv", true
	case 171:
		return "multiplex", true
	case 172:
		return "cl-1", true
	case 173:
		return "xyplex-mux", true
	case 174:
		return "mailq", true
	case 175:
		return "vmnet", true
	case 176:
		return "genrad-mux", true
	case 177:
		return "xdmcp", true
	case 178:
		return "nextstep", true
	case 179:
		return "bgp", true
	case 180:
		return "ris", true
	case 181:
		return "unify", true
	case 182:
		return "audit", true
	case 183:
		return "ocbinder", true
	case 184:
		return "ocserver", true
	case 185:
		return "remote-kis", true
	case 186:
		return "kis", true
	case 187:
		return "aci", true
	case 188:
		return "mumps", true
	case 189:
		return "qft", true
	case 190:
		return "gacp", true
	case 191:
		return "prospero", true
	case 192:
		return "osu-nms", true
	case 193:
		return "srmp", true
	case 194:
		return "irc", true
	case 195:
		return "dn6-nlm-aud", true
	case 196:
		return "dn6-smm-red", true
	case 197:
		return "dls", true
	case 198:
		return "dls-mon", true
	case 199:
		return "smux", true
	case 200:
		return "src", true
	case 201:
		return "at-rtmp", true
	case 202:
		return "at-nbp", true
	case 203:
		return "at-3", true
	case 204:
		return "at-echo", true
	case 205:
		return "at-5", true
	case 206:
		return "at-zis", true
	case 207:
		return "at-7", true
	case 208:
		return "at-8", true
	case 209:
		return "qmtp", true
	case 210:
		return "z39-50", true
	case 211:
		return "914c-g", true
	case 212:
		return "anet", true
	case 213:
		return "ipx", true
	case 214:
		return "vmpwscs", true
	case 215:
		return "softpc", true
	case 216:
		return "CAIlic", true
	case 217:
		return "dbase", true
	case 218:
		return "mpp", true
	case 219:
		return "uarps", true
	case 220:
		return "imap3", true
	case 221:
		return "fln-spx", true
	case 222:
		return "rsh-spx", true
	case 223:
		return "cdc", true
	case 224:
		return "masqdialer", true
	case 242:
		return "direct", true
	case 243:
		return "sur-meas", true
	case 244:
		return "inbusiness", true
	case 245:
		return "link", true
	case 246:
		return "dsp3270", true
	case 247:
		return "subntbcst-tftp", true
	case 248:
		return "bhfhs", true
	case 256:
		return "rap", true
	case 257:
		return "set", true
	case 259:
		return "esro-gen", true
	case 260:
		return "openport", true
	case 261:
		return "nsiiops", true
	case 262:
		return "arcisdms", true
	case 263:
		return "hdap", true
	case 264:
		return "bgmp", true
	case 265:
		return "x-bone-ctl", true
	case 266:
		return "sst", true
	case 267:
		return "td-service", true
	case 268:
		return "td-replica", true
	case 269:
		return "manet", true
	case 270:
		return "gist", true
	case 280:
		return "http-mgmt", true
	case 281:
		return "personal-link", true
	case 282:
		return "cableport-ax", true
	case 283:
		return "rescap", true
	case 284:
		return "corerjd", true
	case 286:
		return "fxp", true
	case 287:
		return "k-block", true
	case 308:
		return "novastorbakcup", true
	case 309:
		return "entrusttime", true
	case 310:
		return "bhmds", true
	case 311:
		return "asip-webadmin", true
	case 312:
		return "vslmp", true
	case 313:
		return "magenta-logic", true
	case 314:
		return "opalis-robot", true
	case 315:
		return "dpsi", true
	case 316:
		return "decauth", true
	case 317:
		return "zannet", true
	case 318:
		return "pkix-timestamp", true
	case 319:
		return "ptp-event", true
	case 320:
		return "ptp-general", true
	case 321:
		return "pip", true
	case 322:
		return "rtsps", true
	case 333:
		return "texar", true
	case 344:
		return "pdap", true
	case 345:
		return "pawserv", true
	case 346:
		return "zserv", true
	case 347:
		return "fatserv", true
	case 348:
		return "csi-sgwp", true
	case 349:
		return "mftp", true
	case 350:
		return "matip-type-a", true
	case 351:
		return "matip-type-b", true
	case 352:
		return "dtag-ste-sb", true
	case 353:
		return "ndsauth", true
	case 354:
		return "bh611", true
	case 355:
		return "datex-asn", true
	case 356:
		return "cloanto-net-1", true
	case 357:
		return "bhevent", true
	case 358:
		return "shrinkwrap", true
	case 359:
		return "nsrmp", true
	case 360:
		return "scoi2odialog", true
	case 361:
		return "semantix", true
	case 362:
		return "srssend", true
	case 363:
		return "rsvp-tunnel", true
	case 364:
		return "aurora-cmgr", true
	case 365:
		return "dtk", true
	case 366:
		return "odmr", true
	case 367:
		return "mortgageware", true
	case 368:
		return "qbikgdp", true
	case 369:
		return "rpc2portmap", true
	case 370:
		return "codaauth2", true
	case 371:
		return "clearcase", true
	case 372:
		return "ulistproc", true
	case 373:
		return "legent-1", true
	case 374:
		return "legent-2", true
	case 375:
		return "hassle", true
	case 376:
		return "nip", true
	case 377:
		return "tnETOS", true
	case 378:
		return "dsETOS", true
	case 379:
		return "is99c", true
	case 380:
		return "is99s", true
	case 381:
		return "hp-collector", true
	case 382:
		return "hp-managed-node", true
	case 383:
		return "hp-alarm-mgr", true
	case 384:
		return "arns", true
	case 385:
		return "ibm-app", true
	case 386:
		return "asa", true
	case 387:
		return "aurp", true
	case 388:
		return "unidata-ldm", true
	case 389:
		return "ldap", true
	case 390:
		return "uis", true
	case 391:
		return "synotics-relay", true
	case 392:
		return "synotics-broker", true
	case 393:
		return "meta5", true
	case 394:
		return "embl-ndt", true
	case 395:
		return "netcp", true
	case 396:
		return "netware-ip", true
	case 397:
		return "mptn", true
	case 398:
		return "kryptolan", true
	case 399:
		return "iso-tsap-c2", true
	case 400:
		return "osb-sd", true
	case 401:
		return "ups", true
	case 402:
		return "genie", true
	case 403:
		return "decap", true
	case 404:
		return "nced", true
	case 405:
		return "ncld", true
	case 406:
		return "imsp", true
	case 407:
		return "timbuktu", true
	case 408:
		return "prm-sm", true
	case 409:
		return "prm-nm", true
	case 410:
		return "decladebug", true
	case 411:
		return "rmt", true
	case 412:
		return "synoptics-trap", true
	case 413:
		return "smsp", true
	case 414:
		return "infoseek", true
	case 415:
		return "bnet", true
	case 416:
		return "silverplatter", true
	case 417:
		return "onmux", true
	case 418:
		return "hyper-g", true
	case 419:
		return "ariel1", true
	case 420:
		return "smpte", true
	case 421:
		return "ariel2", true
	case 422:
		return "ariel3", true
	case 423:
		return "opc-job-start", true
	case 424:
		return "opc-job-track", true
	case 425:
		return "icad-el", true
	case 426:
		return "smartsdp", true
	case 427:
		return "svrloc", true
	case 428:
		return "ocs-cmu", true
	case 429:
		return "ocs-amu", true
	case 430:
		return "utmpsd", true
	case 431:
		return "utmpcd", true
	case 432:
		return "iasd", true
	case 433:
		return "nnsp", true
	case 434:
		return "mobileip-agent", true
	case 435:
		return "mobilip-mn", true
	case 436:
		return "dna-cml", true
	case 437:
		return "comscm", true
	case 438:
		return "dsfgw", true
	case 439:
		return "dasp", true
	case 440:
		return "sgcp", true
	case 441:
		return "decvms-sysmgt", true
	case 442:
		return "cvc-hostd", true
	case 443:
		return "https", true
	case 444:
		return "snpp", true
	case 445:
		return "microsoft-ds", true
	case 446:
		return "ddm-rdb", true
	case 447:
		return "ddm-dfm", true
	case 448:
		return "ddm-ssl", true
	case 449:
		return "as-servermap", true
	case 450:
		return "tserver", true
	case 451:
		return "sfs-smp-net", true
	case 452:
		return "sfs-config", true
	case 453:
		return "creativeserver", true
	case 454:
		return "contentserver", true
	case 455:
		return "creativepartnr", true
	case 456:
		return "macon-udp", true
	case 457:
		return "scohelp", true
	case 458:
		return "appleqtc", true
	case 459:
		return "ampr-rcmd", true
	case 460:
		return "skronk", true
	case 461:
		return "datasurfsrv", true
	case 462:
		return "datasurfsrvsec", true
	case 463:
		return "alpes", true
	case 464:
		return "kpasswd", true
	case 465:
		return "igmpv3lite", true
	case 466:
		return "digital-vrc", true
	case 467:
		return "mylex-mapd", true
	case 468:
		return "photuris", true
	case 469:
		return "rcp", true
	case 470:
		return "scx-proxy", true
	case 471:
		return "mondex", true
	case 472:
		return "ljk-login", true
	case 473:
		return "hybrid-pop", true
	case 474:
		return "tn-tl-w2", true
	case 475:
		return "tcpnethaspsrv", true
	case 476:
		return "tn-tl-fd1", true
	case 477:
		return "ss7ns", true
	case 478:
		return "spsc", true
	case 479:
		return "iafserver", true
	case 480:
		return "iafdbase", true
	case 481:
		return "ph", true
	case 482:
		return "bgs-nsi", true
	case 483:
		return "ulpnet", true
	case 484:
		return "integra-sme", true
	case 485:
		return "powerburst", true
	case 486:
		return "avian", true
	case 487:
		return "saft", true
	case 488:
		return "gss-http", true
	case 489:
		return "nest-protocol", true
	case 490:
		return "micom-pfs", true
	case 491:
		return "go-login", true
	case 492:
		return "ticf-1", true
	case 493:
		return "ticf-2", true
	case 494:
		return "pov-ray", true
	case 495:
		return "intecourier", true
	case 496:
		return "pim-rp-disc", true
	case 497:
		return "retrospect", true
	case 498:
		return "siam", true
	case 499:
		return "iso-ill", true
	case 500:
		return "isakmp", true
	case 501:
		return "stmf", true
	case 502:
		return "mbap", true
	case 503:
		return "intrinsa", true
	case 504:
		return "citadel", true
	case 505:
		return "mailbox-lm", true
	case 506:
		return "ohimsrv", true
	case 507:
		return "crs", true
	case 508:
		return "xvttp", true
	case 509:
		return "snare", true
	case 510:
		return "fcp", true
	case 511:
		return "passgo", true
	case 512:
		return "comsat", true
	case 513:
		return "who", true
	case 514:
		return "syslog", true
	case 515:
		return "printer", true
	case 516:
		return "videotex", true
	case 517:
		return "talk", true
	case 518:
		return "ntalk", true
	case 519:
		return "utime", true
	case 520:
		return "router", true
	case 521:
		return "ripng", true
	case 522:
		return "ulp", true
	case 523:
		return "ibm-db2", true
	case 524:
		return "ncp", true
	case 525:
		return "timed", true
	case 526:
		return "tempo", true
	case 527:
		return "stx", true
	case 528:
		return "custix", true
	case 529:
		return "irc-serv", true
	case 530:
		return "courier", true
	case 531:
		return "conference", true
	case 532:
		return "netnews", true
	case 533:
		return "netwall", true
	case 534:
		return "windream", true
	case 535:
		return "iiop", true
	case 536:
		return "opalis-rdv", true
	case 537:
		return "nmsp", true
	case 538:
		return "gdomap", true
	case 539:
		return "apertus-ldp", true
	case 540:
		return "uucp", true
	case 541:
		return "uucp-rlogin", true
	case 542:
		return "commerce", true
	case 543:
		return "klogin", true
	case 544:
		return "kshell", true
	case 545:
		return "appleqtcsrvr", true
	case 546:
		return "dhcpv6-client", true
	case 547:
		return "dhcpv6-server", true
	case 548:
		return "afpovertcp", true
	case 549:
		return "idfp", true
	case 550:
		return "new-rwho", true
	case 551:
		return "cybercash", true
	case 552:
		return "devshr-nts", true
	case 553:
		return "pirp", true
	case 554:
		return "rtsp", true
	case 555:
		return "dsf", true
	case 556:
		return "remotefs", true
	case 557:
		return "openvms-sysipc", true
	case 558:
		return "sdnskmp", true
	case 559:
		return "teedtap", true
	case 560:
		return "rmonitor", true
	case 561:
		return "monitor", true
	case 562:
		return "chshell", true
	case 563:
		return "nntps", true
	case 564:
		return "9pfs", true
	case 565:
		return "whoami", true
	case 566:
		return "streettalk", true
	case 567:
		return "banyan-rpc", true
	case 568:
		return "ms-shuttle", true
	case 569:
		return "ms-rome", true
	case 570:
		return "meter", true
	case 571:
		return "meter", true
	case 572:
		return "sonar", true
	case 573:
		return "banyan-vip", true
	case 574:
		return "ftp-agent", true
	case 575:
		return "vemmi", true
	case 576:
		return "ipcd", true
	case 577:
		return "vnas", true
	case 578:
		return "ipdd", true
	case 579:
		return "decbsrv", true
	case 580:
		return "sntp-heartbeat", true
	case 581:
		return "bdp", true
	case 582:
		return "scc-security", true
	case 583:
		return "philips-vc", true
	case 584:
		return "keyserver", true
	case 586:
		return "password-chg", true
	case 587:
		return "submission", true
	case 588:
		return "cal", true
	case 589:
		return "eyelink", true
	case 590:
		return "tns-cml", true
	case 591:
		return "http-alt", true
	case 592:
		return "eudora-set", true
	case 593:
		return "http-rpc-epmap", true
	case 594:
		return "tpip", true
	case 595:
		return "cab-protocol", true
	case 596:
		return "smsd", true
	case 597:
		return "ptcnameservice", true
	case 598:
		return "sco-websrvrmg3", true
	case 599:
		return "acp", true
	case 600:
		return "ipcserver", true
	case 601:
		return "syslog-conn", true
	case 602:
		return "xmlrpc-beep", true
	case 603:
		return "idxp", true
	case 604:
		return "tunnel", true
	case 605:
		return "soap-beep", true
	case 606:
		return "urm", true
	case 607:
		return "nqs", true
	case 608:
		return "sift-uft", true
	case 609:
		return "npmp-trap", true
	case 610:
		return "npmp-local", true
	case 611:
		return "npmp-gui", true
	case 612:
		return "hmmp-ind", true
	case 613:
		return "hmmp-op", true
	case 614:
		return "sshell", true
	case 615:
		return "sco-inetmgr", true
	case 616:
		return "sco-sysmgr", true
	case 617:
		return "sco-dtmgr", true
	case 618:
		return "dei-icda", true
	case 619:
		return "compaq-evm", true
	case 620:
		return "sco-websrvrmgr", true
	case 621:
		return "escp-ip", true
	case 622:
		return "collaborator", true
	case 623:
		return "asf-rmcp", true
	case 624:
		return "cryptoadmin", true
	case 625:
		return "dec-dlm", true
	case 626:
		return "asia", true
	case 627:
		return "passgo-tivoli", true
	case 628:
		return "qmqp", true
	case 629:
		return "3com-amp3", true
	case 630:
		return "rda", true
	case 631:
		return "ipp", true
	case 632:
		return "bmpp", true
	case 633:
		return "servstat", true
	case 634:
		return "ginad", true
	case 635:
		return "rlzdbase", true
	case 636:
		return "ldaps", true
	case 637:
		return "lanserver", true
	case 638:
		return "mcns-sec", true
	case 639:
		return "msdp", true
	case 640:
		return "entrust-sps", true
	case 641:
		return "repcmd", true
	case 642:
		return "esro-emsdp", true
	case 643:
		return "sanity", true
	case 644:
		return "dwr", true
	case 645:
		return "pssc", true
	case 646:
		return "ldp", true
	case 647:
		return "dhcp-failover", true
	case 648:
		return "rrp", true
	case 649:
		return "cadview-3d", true
	case 650:
		return "obex", true
	case 651:
		return "ieee-mms", true
	case 652:
		return "hello-port", true
	case 653:
		return "repscmd", true
	case 654:
		return "aodv", true
	case 655:
		return "tinc", true
	case 656:
		return "spmp", true
	case 657:
		return "rmc", true
	case 658:
		return "tenfold", true
	case 660:
		return "mac-srvr-admin", true
	case 661:
		return "hap", true
	case 662:
		return "pftp", true
	case 663:
		return "purenoise", true
	case 664:
		return "asf-secure-rmcp", true
	case 665:
		return "sun-dr", true
	case 666:
		return "mdqs", true
	case 667:
		return "disclose", true
	case 668:
		return "mecomm", true
	case 669:
		return "meregister", true
	case 670:
		return "vacdsm-sws", true
	case 671:
		return "vacdsm-app", true
	case 672:
		return "vpps-qua", true
	case 673:
		return "cimplex", true
	case 674:
		return "acap", true
	case 675:
		return "dctp", true
	case 676:
		return "vpps-via", true
	case 677:
		return "vpp", true
	case 678:
		return "ggf-ncp", true
	case 679:
		return "mrm", true
	case 680:
		return "entrust-aaas", true
	case 681:
		return "entrust-aams", true
	case 682:
		return "xfr", true
	case 683:
		return "corba-iiop", true
	case 684:
		return "corba-iiop-ssl", true
	case 685:
		return "mdc-portmapper", true
	case 686:
		return "hcp-wismar", true
	case 687:
		return "asipregistry", true
	case 688:
		return "realm-rusd", true
	case 689:
		return "nmap", true
	case 690:
		return "vatp", true
	case 691:
		return "msexch-routing", true
	case 692:
		return "hyperwave-isp", true
	case 693:
		return "connendp", true
	case 694:
		return "ha-cluster", true
	case 695:
		return "ieee-mms-ssl", true
	case 696:
		return "rushd", true
	case 697:
		return "uuidgen", true
	case 698:
		return "olsr", true
	case 699:
		return "accessnetwork", true
	case 700:
		return "epp", true
	case 701:
		return "lmp", true
	case 702:
		return "iris-beep", true
	case 704:
		return "elcsd", true
	case 705:
		return "agentx", true
	case 706:
		return "silc", true
	case 707:
		return "borland-dsj", true
	case 709:
		return "entrust-kmsh", true
	case 710:
		return "entrust-ash", true
	case 711:
		return "cisco-tdp", true
	case 712:
		return "tbrpf", true
	case 713:
		return "iris-xpc", true
	case 714:
		return "iris-xpcs", true
	case 715:
		return "iris-lwz", true
	case 716:
		return "pana", true
	case 729:
		return "netviewdm1", true
	case 730:
		return "netviewdm2", true
	case 731:
		return "netviewdm3", true
	case 741:
		return "netgw", true
	case 742:
		return "netrcs", true
	case 744:
		return "flexlm", true
	case 747:
		return "fujitsu-dev", true
	case 748:
		return "ris-cm", true
	case 749:
		return "kerberos-adm", true
	case 750:
		return "loadav", true
	case 751:
		return "pump", true
	case 752:
		return "qrh", true
	case 753:
		return "rrh", true
	case 754:
		return "tell", true
	case 758:
		return "nlogin", true
	case 759:
		return "con", true
	case 760:
		return "ns", true
	case 761:
		return "rxe", true
	case 762:
		return "quotad", true
	case 763:
		return "cycleserv", true
	case 764:
		return "omserv", true
	case 765:
		return "webster", true
	case 767:
		return "phonebook", true
	case 769:
		return "vid", true
	case 770:
		return "cadlock", true
	case 771:
		return "rtip", true
	case 772:
		return "cycleserv2", true
	case 773:
		return "notify", true
	case 774:
		return "acmaint-dbd", true
	case 775:
		return "acmaint-transd", true
	case 776:
		return "wpages", true
	case 777:
		return "multiling-http", true
	case 780:
		return "wpgs", true
	case 800:
		return "mdbs-daemon", true
	case 801:
		return "device", true
	case 802:
		return "mbap-s", true
	case 810:
		return "fcp-udp", true
	case 828:
		return "itm-mcell-s", true
	case 829:
		return "pkix-3-ca-ra", true
	case 830:
		return "netconf-ssh", true
	case 831:
		return "netconf-beep", true
	case 832:
		return "netconfsoaphttp", true
	case 833:
		return "netconfsoapbeep", true
	case 847:
		return "dhcp-failover2", true
	case 848:
		return "gdoi", true
	case 853:
		return "domain-s", true
	case 854:
		return "dlep", true
	case 860:
		return "iscsi", true
	case 861:
		return "owamp-test", true
	case 862:
		return "twamp-test", true
	case 873:
		return "rsync", true
	case 886:
		return "iclcnet-locate", true
	case 887:
		return "iclcnet-svinfo", true
	case 888:
		return "accessbuilder", true
	case 900:
		return "omginitialrefs", true
	case 901:
		return "smpnameres", true
	case 902:
		return "ideafarm-door", true
	case 903:
		return "ideafarm-panic", true
	case 910:
		return "kink", true
	case 911:
		return "xact-backup", true
	case 912:
		return "apex-mesh", true
	case 913:
		return "apex-edge", true
	case 914:
		return "rift-lies", true
	case 915:
		return "rift-ties", true
	case 989:
		return "ftps-data", true
	case 990:
		return "ftps", true
	case 991:
		return "nas", true
	case 992:
		return "telnets", true
	case 995:
		return "pop3s", true
	case 996:
		return "vsinet", true
	case 997:
		return "maitrd", true
	case 998:
		return "puparp", true
	case 999:
		return "applix", true
	case 1000:
		return "cadlock2", true
	case 1010:
		return "surf", true
	case 1021:
		return "exp1", true
	case 1022:
		return "exp2", true
	case 1025:
		return "blackjack", true
	case 1026:
		return "cap", true
	case 1027:
		return "6a44", true
	case 1029:
		return "solid-mux", true
	case 1033:
		return "netinfo-local", true
	case 1034:
		return "activesync", true
	case 1035:
		return "mxxrlogin", true
	case 1036:
		return "nsstp", true
	case 1037:
		return "ams", true
	case 1038:
		return "mtqp", true
	case 1039:
		return "sbl", true
	case 1040:
		return "netarx", true
	case 1041:
		return "danf-ak2", true
	case 1042:
		return "afrog", true
	case 1043:
		return "boinc-client", true
	case 1044:
		return "dcutility", true
	case 1045:
		return "fpitp", true
	case 1046:
		return "wfremotertm", true
	case 1047:
		return "neod1", true
	case 1048:
		return "neod2", true
	case 1049:
		return "td-postman", true
	case 1050:
		return "cma", true
	case 1051:
		return "optima-vnet", true
	case 1052:
		return "ddt", true
	case 1053:
		return "remote-as", true
	case 1054:
		return "brvread", true
	case 1055:
		return "ansyslmd", true
	case 1056:
		return "vfo", true
	case 1057:
		return "startron", true
	case 1058:
		return "nim", true
	case 1059:
		return "nimreg", true
	case 1060:
		return "polestar", true
	case 1061:
		return "kiosk", true
	case 1062:
		return "veracity", true
	case 1063:
		return "kyoceranetdev", true
	case 1064:
		return "jstel", true
	case 1065:
		return "syscomlan", true
	case 1066:
		return "fpo-fns", true
	case 1067:
		return "instl-boots", true
	case 1068:
		return "instl-bootc", true
	case 1069:
		return "cognex-insight", true
	case 1070:
		return "gmrupdateserv", true
	case 1071:
		return "bsquare-voip", true
	case 1072:
		return "cardax", true
	case 1073:
		return "bridgecontrol", true
	case 1074:
		return "warmspotMgmt", true
	case 1075:
		return "rdrmshc", true
	case 1076:
		return "dab-sti-c", true
	case 1077:
		return "imgames", true
	case 1078:
		return "avocent-proxy", true
	case 1079:
		return "asprovatalk", true
	case 1080:
		return "socks", true
	case 1081:
		return "pvuniwien", true
	case 1082:
		return "amt-esd-prot", true
	case 1083:
		return "ansoft-lm-1", true
	case 1084:
		return "ansoft-lm-2", true
	case 1085:
		return "webobjects", true
	case 1086:
		return "cplscrambler-lg", true
	case 1087:
		return "cplscrambler-in", true
	case 1088:
		return "cplscrambler-al", true
	case 1089:
		return "ff-annunc", true
	case 1090:
		return "ff-fms", true
	case 1091:
		return "ff-sm", true
	case 1092:
		return "obrpd", true
	case 1093:
		return "proofd", true
	case 1094:
		return "rootd", true
	case 1095:
		return "nicelink", true
	case 1096:
		return "cnrprotocol", true
	case 1097:
		return "sunclustermgr", true
	case 1098:
		return "rmiactivation", true
	case 1099:
		return "rmiregistry", true
	case 1100:
		return "mctp", true
	case 1101:
		return "pt2-discover", true
	case 1102:
		return "adobeserver-1", true
	case 1103:
		return "adobeserver-2", true
	case 1104:
		return "xrl", true
	case 1105:
		return "ftranhc", true
	case 1106:
		return "isoipsigport-1", true
	case 1107:
		return "isoipsigport-2", true
	case 1108:
		return "ratio-adp", true
	case 1110:
		return "nfsd-keepalive", true
	case 1111:
		return "lmsocialserver", true
	case 1112:
		return "icp", true
	case 1113:
		return "ltp-deepspace", true
	case 1114:
		return "mini-sql", true
	case 1115:
		return "ardus-trns", true
	case 1116:
		return "ardus-cntl", true
	case 1117:
		return "ardus-mtrns", true
	case 1118:
		return "sacred", true
	case 1119:
		return "bnetgame", true
	case 1120:
		return "bnetfile", true
	case 1121:
		return "rmpp", true
	case 1122:
		return "availant-mgr", true
	case 1123:
		return "murray", true
	case 1124:
		return "hpvmmcontrol", true
	case 1125:
		return "hpvmmagent", true
	case 1126:
		return "hpvmmdata", true
	case 1127:
		return "kwdb-commn", true
	case 1128:
		return "saphostctrl", true
	case 1129:
		return "saphostctrls", true
	case 1130:
		return "casp", true
	case 1131:
		return "caspssl", true
	case 1132:
		return "kvm-via-ip", true
	case 1133:
		return "dfn", true
	case 1134:
		return "aplx", true
	case 1135:
		return "omnivision", true
	case 1136:
		return "hhb-gateway", true
	case 1137:
		return "trim", true
	case 1138:
		return "encrypted-admin", true
	case 1139:
		return "evm", true
	case 1140:
		return "autonoc", true
	case 1141:
		return "mxomss", true
	case 1142:
		return "edtools", true
	case 1143:
		return "imyx", true
	case 1144:
		return "fuscript", true
	case 1145:
		return "x9-icue", true
	case 1146:
		return "audit-transfer", true
	case 1147:
		return "capioverlan", true
	case 1148:
		return "elfiq-repl", true
	case 1149:
		return "bvtsonar", true
	case 1150:
		return "blaze", true
	case 1151:
		return "unizensus", true
	case 1152:
		return "winpoplanmess", true
	case 1153:
		return "c1222-acse", true
	case 1154:
		return "resacommunity", true
	case 1155:
		return "nfa", true
	case 1156:
		return "iascontrol-oms", true
	case 1157:
		return "iascontrol", true
	case 1158:
		return "dbcontrol-oms", true
	case 1159:
		return "oracle-oms", true
	case 1160:
		return "olsv", true
	case 1161:
		return "health-polling", true
	case 1162:
		return "health-trap", true
	case 1163:
		return "sddp", true
	case 1164:
		return "qsm-proxy", true
	case 1165:
		return "qsm-gui", true
	case 1166:
		return "qsm-remote", true
	case 1167:
		return "cisco-ipsla", true
	case 1168:
		return "vchat", true
	case 1169:
		return "tripwire", true
	case 1170:
		return "atc-lm", true
	case 1171:
		return "atc-appserver", true
	case 1172:
		return "dnap", true
	case 1173:
		return "d-cinema-rrp", true
	case 1174:
		return "fnet-remote-ui", true
	case 1175:
		return "dossier", true
	case 1176:
		return "indigo-server", true
	case 1177:
		return "dkmessenger", true
	case 1178:
		return "sgi-storman", true
	case 1179:
		return "b2n", true
	case 1180:
		return "mc-client", true
	case 1181:
		return "3comnetman", true
	case 1182:
		return "accelenet-data", true
	case 1183:
		return "llsurfup-http", true
	case 1184:
		return "llsurfup-https", true
	case 1185:
		return "catchpole", true
	case 1186:
		return "mysql-cluster", true
	case 1187:
		return "alias", true
	case 1188:
		return "hp-webadmin", true
	case 1189:
		return "unet", true
	case 1190:
		return "commlinx-avl", true
	case 1191:
		return "gpfs", true
	case 1192:
		return "caids-sensor", true
	case 1193:
		return "fiveacross", true
	case 1194:
		return "openvpn", true
	case 1195:
		return "rsf-1", true
	case 1196:
		return "netmagic", true
	case 1197:
		return "carrius-rshell", true
	case 1198:
		return "cajo-discovery", true
	case 1199:
		return "dmidi", true
	case 1200:
		return "scol", true
	case 1201:
		return "nucleus-sand", true
	case 1202:
		return "caiccipc", true
	case 1203:
		return "ssslic-mgr", true
	case 1204:
		return "ssslog-mgr", true
	case 1205:
		return "accord-mgc", true
	case 1206:
		return "anthony-data", true
	case 1207:
		return "metasage", true
	case 1208:
		return "seagull-ais", true
	case 1209:
		return "ipcd3", true
	case 1210:
		return "eoss", true
	case 1211:
		return "groove-dpp", true
	case 1212:
		return "lupa", true
	case 1213:
		return "mpc-lifenet", true
	case 1214:
		return "kazaa", true
	case 1215:
		return "scanstat-1", true
	case 1216:
		return "etebac5", true
	case 1217:
		return "hpss-ndapi", true
	case 1218:
		return "aeroflight-ads", true
	case 1219:
		return "aeroflight-ret", true
	case 1220:
		return "qt-serveradmin", true
	case 1221:
		return "sweetware-apps", true
	case 1222:
		return "nerv", true
	case 1223:
		return "tgp", true
	case 1224:
		return "vpnz", true
	case 1225:
		return "slinkysearch", true
	case 1226:
		return "stgxfws", true
	case 1227:
		return "dns2go", true
	case 1228:
		return "florence", true
	case 1229:
		return "zented", true
	case 1230:
		return "periscope", true
	case 1231:
		return "menandmice-lpm", true
	case 1232:
		return "first-defense", true
	case 1233:
		return "univ-appserver", true
	case 1234:
		return "search-agent", true
	case 1235:
		return "mosaicsyssvc1", true
	case 1236:
		return "bvcontrol", true
	case 1237:
		return "tsdos390", true
	case 1238:
		return "hacl-qs", true
	case 1239:
		return "nmsd", true
	case 1240:
		return "instantia", true
	case 1241:
		return "nessus", true
	case 1242:
		return "nmasoverip", true
	case 1243:
		return "serialgateway", true
	case 1244:
		return "isbconference1", true
	case 1245:
		return "isbconference2", true
	case 1246:
		return "payrouter", true
	case 1247:
		return "visionpyramid", true
	case 1248:
		return "hermes", true
	case 1249:
		return "mesavistaco", true
	case 1250:
		return "swldy-sias", true
	case 1251:
		return "servergraph", true
	case 1252:
		return "bspne-pcc", true
	case 1253:
		return "q55-pcc", true
	case 1254:
		return "de-noc", true
	case 1255:
		return "de-cache-query", true
	case 1256:
		return "de-server", true
	case 1257:
		return "shockwave2", true
	case 1258:
		return "opennl", true
	case 1259:
		return "opennl-voice", true
	case 1260:
		return "ibm-ssd", true
	case 1261:
		return "mpshrsv", true
	case 1262:
		return "qnts-orb", true
	case 1263:
		return "dka", true
	case 1264:
		return "prat", true
	case 1265:
		return "dssiapi", true
	case 1266:
		return "dellpwrappks", true
	case 1267:
		return "epc", true
	case 1268:
		return "propel-msgsys", true
	case 1269:
		return "watilapp", true
	case 1270:
		return "opsmgr", true
	case 1271:
		return "excw", true
	case 1272:
		return "cspmlockmgr", true
	case 1273:
		return "emc-gateway", true
	case 1274:
		return "t1distproc", true
	case 1275:
		return "ivcollector", true
	case 1277:
		return "miva-mqs", true
	case 1278:
		return "dellwebadmin-1", true
	case 1279:
		return "dellwebadmin-2", true
	case 1280:
		return "pictrography", true
	case 1281:
		return "healthd", true
	case 1282:
		return "emperion", true
	case 1283:
		return "productinfo", true
	case 1284:
		return "iee-qfx", true
	case 1285:
		return "neoiface", true
	case 1286:
		return "netuitive", true
	case 1287:
		return "routematch", true
	case 1288:
		return "navbuddy", true
	case 1289:
		return "jwalkserver", true
	case 1290:
		return "winjaserver", true
	case 1291:
		return "seagulllms", true
	case 1292:
		return "dsdn", true
	case 1293:
		return "pkt-krb-ipsec", true
	case 1294:
		return "cmmdriver", true
	case 1295:
		return "ehtp", true
	case 1296:
		return "dproxy", true
	case 1297:
		return "sdproxy", true
	case 1298:
		return "lpcp", true
	case 1299:
		return "hp-sci", true
	case 1300:
		return "h323hostcallsc", true
	case 1303:
		return "sftsrv", true
	case 1304:
		return "boomerang", true
	case 1305:
		return "pe-mike", true
	case 1306:
		return "re-conn-proto", true
	case 1307:
		return "pacmand", true
	case 1308:
		return "odsi", true
	case 1309:
		return "jtag-server", true
	case 1310:
		return "husky", true
	case 1311:
		return "rxmon", true
	case 1312:
		return "sti-envision", true
	case 1313:
		return "bmc-patroldb", true
	case 1314:
		return "pdps", true
	case 1315:
		return "els", true
	case 1316:
		return "exbit-escp", true
	case 1317:
		return "vrts-ipcserver", true
	case 1318:
		return "krb5gatekeeper", true
	case 1319:
		return "amx-icsp", true
	case 1320:
		return "amx-axbnet", true
	case 1321:
		return "pip", true
	case 1322:
		return "novation", true
	case 1323:
		return "brcd", true
	case 1324:
		return "delta-mcp", true
	case 1325:
		return "dx-instrument", true
	case 1326:
		return "wimsic", true
	case 1327:
		return "ultrex", true
	case 1328:
		return "ewall", true
	case 1329:
		return "netdb-export", true
	case 1330:
		return "streetperfect", true
	case 1331:
		return "intersan", true
	case 1332:
		return "pcia-rxp-b", true
	case 1333:
		return "passwrd-policy", true
	case 1334:
		return "writesrv", true
	case 1335:
		return "digital-notary", true
	case 1336:
		return "ischat", true
	case 1337:
		return "menandmice-dns", true
	case 1338:
		return "wmc-log-svc", true
	case 1339:
		return "kjtsiteserver", true
	case 1340:
		return "naap", true
	case 1341:
		return "qubes", true
	case 1342:
		return "esbroker", true
	case 1343:
		return "re101", true
	case 1344:
		return "icap", true
	case 1345:
		return "vpjp", true
	case 1346:
		return "alta-ana-lm", true
	case 1347:
		return "bbn-mmc", true
	case 1348:
		return "bbn-mmx", true
	case 1349:
		return "sbook", true
	case 1350:
		return "editbench", true
	case 1351:
		return "equationbuilder", true
	case 1352:
		return "lotusnote", true
	case 1353:
		return "relief", true
	case 1354:
		return "XSIP-network", true
	case 1355:
		return "intuitive-edge", true
	case 1356:
		return "cuillamartin", true
	case 1357:
		return "pegboard", true
	case 1358:
		return "connlcli", true
	case 1359:
		return "ftsrv", true
	case 1360:
		return "mimer", true
	case 1361:
		return "linx", true
	case 1362:
		return "timeflies", true
	case 1363:
		return "ndm-requester", true
	case 1364:
		return "ndm-server", true
	case 1365:
		return "adapt-sna", true
	case 1366:
		return "netware-csp", true
	case 1367:
		return "dcs", true
	case 1368:
		return "screencast", true
	case 1369:
		return "gv-us", true
	case 1370:
		return "us-gv", true
	case 1371:
		return "fc-cli", true
	case 1372:
		return "fc-ser", true
	case 1373:
		return "chromagrafx", true
	case 1374:
		return "molly", true
	case 1375:
		return "bytex", true
	case 1376:
		return "ibm-pps", true
	case 1377:
		return "cichlid", true
	case 1378:
		return "elan", true
	case 1379:
		return "dbreporter", true
	case 1380:
		return "telesis-licman", true
	case 1381:
		return "apple-licman", true
	case 1382:
		return "udt-os", true
	case 1383:
		return "gwha", true
	case 1384:
		return "os-licman", true
	case 1385:
		return "atex-elmd", true
	case 1386:
		return "checksum", true
	case 1387:
		return "cadsi-lm", true
	case 1388:
		return "objective-dbc", true
	case 1389:
		return "iclpv-dm", true
	case 1390:
		return "iclpv-sc", true
	case 1391:
		return "iclpv-sas", true
	case 1392:
		return "iclpv-pm", true
	case 1393:
		return "iclpv-nls", true
	case 1394:
		return "iclpv-nlc", true
	case 1395:
		return "iclpv-wsm", true
	case 1396:
		return "dvl-activemail", true
	case 1397:
		return "audio-activmail", true
	case 1398:
		return "video-activmail", true
	case 1399:
		return "cadkey-licman", true
	case 1400:
		return "cadkey-tablet", true
	case 1401:
		return "goldleaf-licman", true
	case 1402:
		return "prm-sm-np", true
	case 1403:
		return "prm-nm-np", true
	case 1404:
		return "igi-lm", true
	case 1405:
		return "ibm-res", true
	case 1406:
		return "netlabs-lm", true
	case 1408:
		return "sophia-lm", true
	case 1409:
		return "here-lm", true
	case 1410:
		return "hiq", true
	case 1411:
		return "af", true
	case 1412:
		return "innosys", true
	case 1413:
		return "innosys-acl", true
	case 1414:
		return "ibm-mqseries", true
	case 1415:
		return "dbstar", true
	case 1416:
		return "novell-lu6-2", true
	case 1417:
		return "timbuktu-srv1", true
	case 1418:
		return "timbuktu-srv2", true
	case 1419:
		return "timbuktu-srv3", true
	case 1420:
		return "timbuktu-srv4", true
	case 1421:
		return "gandalf-lm", true
	case 1422:
		return "autodesk-lm", true
	case 1423:
		return "essbase", true
	case 1424:
		return "hybrid", true
	case 1425:
		return "zion-lm", true
	case 1426:
		return "sais", true
	case 1427:
		return "mloadd", true
	case 1428:
		return "informatik-lm", true
	case 1429:
		return "nms", true
	case 1430:
		return "tpdu", true
	case 1431:
		return "rgtp", true
	case 1432:
		return "blueberry-lm", true
	case 1433:
		return "ms-sql-s", true
	case 1434:
		return "ms-sql-m", true
	case 1435:
		return "ibm-cics", true
	case 1436:
		return "saism", true
	case 1437:
		return "tabula", true
	case 1438:
		return "eicon-server", true
	case 1439:
		return "eicon-x25", true
	case 1440:
		return "eicon-slp", true
	case 1441:
		return "cadis-1", true
	case 1442:
		return "cadis-2", true
	case 1443:
		return "ies-lm", true
	case 1444:
		return "marcam-lm", true
	case 1445:
		return "proxima-lm", true
	case 1446:
		return "ora-lm", true
	case 1447:
		return "apri-lm", true
	case 1448:
		return "oc-lm", true
	case 1449:
		return "peport", true
	case 1450:
		return "dwf", true
	case 1451:
		return "infoman", true
	case 1452:
		return "gtegsc-lm", true
	case 1453:
		return "genie-lm", true
	case 1454:
		return "interhdl-elmd", true
	case 1455:
		return "esl-lm", true
	case 1456:
		return "dca", true
	case 1457:
		return "valisys-lm", true
	case 1458:
		return "nrcabq-lm", true
	case 1459:
		return "proshare1", true
	case 1460:
		return "proshare2", true
	case 1461:
		return "ibm-wrless-lan", true
	case 1462:
		return "world-lm", true
	case 1463:
		return "nucleus", true
	case 1464:
		return "msl-lmd", true
	case 1465:
		return "pipes", true
	case 1466:
		return "oceansoft-lm", true
	case 1467:
		return "csdmbase", true
	case 1468:
		return "csdm", true
	case 1469:
		return "aal-lm", true
	case 1470:
		return "uaiact", true
	case 1471:
		return "csdmbase", true
	case 1472:
		return "csdm", true
	case 1473:
		return "openmath", true
	case 1474:
		return "telefinder", true
	case 1475:
		return "taligent-lm", true
	case 1476:
		return "clvm-cfg", true
	case 1477:
		return "ms-sna-server", true
	case 1478:
		return "ms-sna-base", true
	case 1479:
		return "dberegister", true
	case 1480:
		return "pacerforum", true
	case 1481:
		return "airs", true
	case 1482:
		return "miteksys-lm", true
	case 1483:
		return "afs", true
	case 1484:
		return "confluent", true
	case 1485:
		return "lansource", true
	case 1486:
		return "nms-topo-serv", true
	case 1487:
		return "localinfosrvr", true
	case 1488:
		return "docstor", true
	case 1489:
		return "dmdocbroker", true
	case 1490:
		return "insitu-conf", true
	case 1492:
		return "stone-design-1", true
	case 1493:
		return "netmap-lm", true
	case 1494:
		return "ica", true
	case 1495:
		return "cvc", true
	case 1496:
		return "liberty-lm", true
	case 1497:
		return "rfx-lm", true
	case 1498:
		return "sybase-sqlany", true
	case 1499:
		return "fhc", true
	case 1500:
		return "vlsi-lm", true
	case 1501:
		return "saiscm", true
	case 1502:
		return "shivadiscovery", true
	case 1503:
		return "imtc-mcs", true
	case 1504:
		return "evb-elm", true
	case 1505:
		return "funkproxy", true
	case 1506:
		return "utcd", true
	case 1507:
		return "symplex", true
	case 1508:
		return "diagmond", true
	case 1509:
		return "robcad-lm", true
	case 1510:
		return "mvx-lm", true
	case 1511:
		return "3l-l1", true
	case 1512:
		return "wins", true
	case 1513:
		return "fujitsu-dtc", true
	case 1514:
		return "fujitsu-dtcns", true
	case 1515:
		return "ifor-protocol", true
	case 1516:
		return "vpad", true
	case 1517:
		return "vpac", true
	case 1518:
		return "vpvd", true
	case 1519:
		return "vpvc", true
	case 1520:
		return "atm-zip-office", true
	case 1521:
		return "ncube-lm", true
	case 1522:
		return "ricardo-lm", true
	case 1523:
		return "cichild-lm", true
	case 1524:
		return "ingreslock", true
	case 1525:
		return "orasrv", true
	case 1526:
		return "pdap-np", true
	case 1527:
		return "tlisrv", true
	case 1528:
		return "norp", true
	case 1529:
		return "coauthor", true
	case 1530:
		return "rap-service", true
	case 1531:
		return "rap-listen", true
	case 1532:
		return "miroconnect", true
	case 1533:
		return "virtual-places", true
	case 1534:
		return "micromuse-lm", true
	case 1535:
		return "ampr-info", true
	case 1536:
		return "ampr-inter", true
	case 1537:
		return "sdsc-lm", true
	case 1538:
		return "3ds-lm", true
	case 1539:
		return "intellistor-lm", true
	case 1540:
		return "rds", true
	case 1541:
		return "rds2", true
	case 1542:
		return "gridgen-elmd", true
	case 1543:
		return "simba-cs", true
	case 1544:
		return "aspeclmd", true
	case 1545:
		return "vistium-share", true
	case 1546:
		return "abbaccuray", true
	case 1547:
		return "laplink", true
	case 1548:
		return "axon-lm", true
	case 1549:
		return "shivasound", true
	case 1550:
		return "3m-image-lm", true
	case 1551:
		return "hecmtl-db", true
	case 1552:
		return "pciarray", true
	case 1553:
		return "sna-cs", true
	case 1554:
		return "caci-lm", true
	case 1555:
		return "livelan", true
	case 1556:
		return "veritas-pbx", true
	case 1557:
		return "arbortext-lm", true
	case 1558:
		return "xingmpeg", true
	case 1559:
		return "web2host", true
	case 1560:
		return "asci-val", true
	case 1561:
		return "facilityview", true
	case 1562:
		return "pconnectmgr", true
	case 1563:
		return "cadabra-lm", true
	case 1564:
		return "pay-per-view", true
	case 1565:
		return "winddlb", true
	case 1566:
		return "corelvideo", true
	case 1567:
		return "jlicelmd", true
	case 1568:
		return "tsspmap", true
	case 1569:
		return "ets", true
	case 1570:
		return "orbixd", true
	case 1571:
		return "rdb-dbs-disp", true
	case 1572:
		return "chip-lm", true
	case 1573:
		return "itscomm-ns", true
	case 1574:
		return "mvel-lm", true
	case 1575:
		return "oraclenames", true
	case 1576:
		return "moldflow-lm", true
	case 1577:
		return "hypercube-lm", true
	case 1578:
		return "jacobus-lm", true
	case 1579:
		return "ioc-sea-lm", true
	case 1580:
		return "tn-tl-r2", true
	case 1581:
		return "mil-2045-47001", true
	case 1582:
		return "msims", true
	case 1583:
		return "simbaexpress", true
	case 1584:
		return "tn-tl-fd2", true
	case 1585:
		return "intv", true
	case 1586:
		return "ibm-abtact", true
	case 1587:
		return "pra-elmd", true
	case 1588:
		return "triquest-lm", true
	case 1589:
		return "vqp", true
	case 1590:
		return "gemini-lm", true
	case 1591:
		return "ncpm-pm", true
	case 1592:
		return "commonspace", true
	case 1593:
		return "mainsoft-lm", true
	case 1594:
		return "sixtrak", true
	case 1595:
		return "radio", true
	case 1596:
		return "radio-bc", true
	case 1597:
		return "orbplus-iiop", true
	case 1598:
		return "picknfs", true
	case 1599:
		return "simbaservices", true
	case 1600:
		return "issd", true
	case 1601:
		return "aas", true
	case 1602:
		return "inspect", true
	case 1603:
		return "picodbc", true
	case 1604:
		return "icabrowser", true
	case 1605:
		return "slp", true
	case 1606:
		return "slm-api", true
	case 1607:
		return "stt", true
	case 1608:
		return "smart-lm", true
	case 1609:
		return "isysg-lm", true
	case 1610:
		return "taurus-wh", true
	case 1611:
		return "ill", true
	case 1612:
		return "netbill-trans", true
	case 1613:
		return "netbill-keyrep", true
	case 1614:
		return "netbill-cred", true
	case 1615:
		return "netbill-auth", true
	case 1616:
		return "netbill-prod", true
	case 1617:
		return "nimrod-agent", true
	case 1618:
		return "skytelnet", true
	case 1619:
		return "xs-openstorage", true
	case 1620:
		return "faxportwinport", true
	case 1621:
		return "softdataphone", true
	case 1622:
		return "ontime", true
	case 1623:
		return "jaleosnd", true
	case 1624:
		return "udp-sr-port", true
	case 1625:
		return "svs-omagent", true
	case 1626:
		return "shockwave", true
	case 1627:
		return "t128-gateway", true
	case 1628:
		return "lontalk-norm", true
	case 1629:
		return "lontalk-urgnt", true
	case 1630:
		return "oraclenet8cman", true
	case 1631:
		return "visitview", true
	case 1632:
		return "pammratc", true
	case 1633:
		return "pammrpc", true
	case 1634:
		return "loaprobe", true
	case 1635:
		return "edb-server1", true
	case 1636:
		return "isdc", true
	case 1637:
		return "islc", true
	case 1638:
		return "ismc", true
	case 1639:
		return "cert-initiator", true
	case 1640:
		return "cert-responder", true
	case 1641:
		return "invision", true
	case 1642:
		return "isis-am", true
	case 1643:
		return "isis-ambc", true
	case 1644:
		return "saiseh", true
	case 1645:
		return "sightline", true
	case 1646:
		return "sa-msg-port", true
	case 1647:
		return "rsap", true
	case 1648:
		return "concurrent-lm", true
	case 1649:
		return "kermit", true
	case 1650:
		return "nkd", true
	case 1651:
		return "shiva-confsrvr", true
	case 1652:
		return "xnmp", true
	case 1653:
		return "alphatech-lm", true
	case 1654:
		return "stargatealerts", true
	case 1655:
		return "dec-mbadmin", true
	case 1656:
		return "dec-mbadmin-h", true
	case 1657:
		return "fujitsu-mmpdc", true
	case 1658:
		return "sixnetudr", true
	case 1659:
		return "sg-lm", true
	case 1660:
		return "skip-mc-gikreq", true
	case 1661:
		return "netview-aix-1", true
	case 1662:
		return "netview-aix-2", true
	case 1663:
		return "netview-aix-3", true
	case 1664:
		return "netview-aix-4", true
	case 1665:
		return "netview-aix-5", true
	case 1666:
		return "netview-aix-6", true
	case 1667:
		return "netview-aix-7", true
	case 1668:
		return "netview-aix-8", true
	case 1669:
		return "netview-aix-9", true
	case 1670:
		return "netview-aix-10", true
	case 1671:
		return "netview-aix-11", true
	case 1672:
		return "netview-aix-12", true
	case 1673:
		return "proshare-mc-1", true
	case 1674:
		return "proshare-mc-2", true
	case 1675:
		return "pdp", true
	case 1676:
		return "netcomm2", true
	case 1677:
		return "groupwise", true
	case 1678:
		return "prolink", true
	case 1679:
		return "darcorp-lm", true
	case 1680:
		return "microcom-sbp", true
	case 1681:
		return "sd-elmd", true
	case 1682:
		return "lanyon-lantern", true
	case 1683:
		return "ncpm-hip", true
	case 1684:
		return "snaresecure", true
	case 1685:
		return "n2nremote", true
	case 1686:
		return "cvmon", true
	case 1687:
		return "nsjtp-ctrl", true
	case 1688:
		return "nsjtp-data", true
	case 1689:
		return "firefox", true
	case 1690:
		return "ng-umds", true
	case 1691:
		return "empire-empuma", true
	case 1692:
		return "sstsys-lm", true
	case 1693:
		return "rrirtr", true
	case 1694:
		return "rrimwm", true
	case 1695:
		return "rrilwm", true
	case 1696:
		return "rrifmm", true
	case 1697:
		return "rrisat", true
	case 1698:
		return "rsvp-encap-1", true
	case 1699:
		return "rsvp-encap-2", true
	case 1700:
		return "mps-raft", true
	case 1701:
		return "l2f", true
	case 1702:
		return "deskshare", true
	case 1703:
		return "hb-engine", true
	case 1704:
		return "bcs-broker", true
	case 1705:
		return "slingshot", true
	case 1706:
		return "jetform", true
	case 1707:
		return "vdmplay", true
	case 1708:
		return "gat-lmd", true
	case 1709:
		return "centra", true
	case 1710:
		return "impera", true
	case 1711:
		return "pptconference", true
	case 1712:
		return "registrar", true
	case 1713:
		return "conferencetalk", true
	case 1714:
		return "sesi-lm", true
	case 1715:
		return "houdini-lm", true
	case 1716:
		return "xmsg", true
	case 1717:
		return "fj-hdnet", true
	case 1718:
		return "h323gatedisc", true
	case 1719:
		return "h323gatestat", true
	case 1720:
		return "h323hostcall", true
	case 1721:
		return "caicci", true
	case 1722:
		return "hks-lm", true
	case 1723:
		return "pptp", true
	case 1724:
		return "csbphonemaster", true
	case 1725:
		return "iden-ralp", true
	case 1726:
		return "iberiagames", true
	case 1727:
		return "winddx", true
	case 1728:
		return "telindus", true
	case 1729:
		return "citynl", true
	case 1730:
		return "roketz", true
	case 1731:
		return "msiccp", true
	case 1732:
		return "proxim", true
	case 1733:
		return "siipat", true
	case 1734:
		return "cambertx-lm", true
	case 1735:
		return "privatechat", true
	case 1736:
		return "street-stream", true
	case 1737:
		return "ultimad", true
	case 1738:
		return "gamegen1", true
	case 1739:
		return "webaccess", true
	case 1740:
		return "encore", true
	case 1741:
		return "cisco-net-mgmt", true
	case 1742:
		return "3Com-nsd", true
	case 1743:
		return "cinegrfx-lm", true
	case 1744:
		return "ncpm-ft", true
	case 1745:
		return "remote-winsock", true
	case 1746:
		return "ftrapid-1", true
	case 1747:
		return "ftrapid-2", true
	case 1748:
		return "oracle-em1", true
	case 1749:
		return "aspen-services", true
	case 1750:
		return "sslp", true
	case 1751:
		return "swiftnet", true
	case 1752:
		return "lofr-lm", true
	case 1754:
		return "oracle-em2", true
	case 1755:
		return "ms-streaming", true
	case 1756:
		return "capfast-lmd", true
	case 1757:
		return "cnhrp", true
	case 1758:
		return "tftp-mcast", true
	case 1759:
		return "spss-lm", true
	case 1760:
		return "www-ldap-gw", true
	case 1761:
		return "cft-0", true
	case 1762:
		return "cft-1", true
	case 1763:
		return "cft-2", true
	case 1764:
		return "cft-3", true
	case 1765:
		return "cft-4", true
	case 1766:
		return "cft-5", true
	case 1767:
		return "cft-6", true
	case 1768:
		return "cft-7", true
	case 1769:
		return "bmc-net-adm", true
	case 1770:
		return "bmc-net-svc", true
	case 1771:
		return "vaultbase", true
	case 1772:
		return "essweb-gw", true
	case 1773:
		return "kmscontrol", true
	case 1774:
		return "global-dtserv", true
	case 1776:
		return "femis", true
	case 1777:
		return "powerguardian", true
	case 1778:
		return "prodigy-intrnet", true
	case 1779:
		return "pharmasoft", true
	case 1780:
		return "dpkeyserv", true
	case 1781:
		return "answersoft-lm", true
	case 1782:
		return "hp-hcip", true
	case 1784:
		return "finle-lm", true
	case 1785:
		return "windlm", true
	case 1786:
		return "funk-logger", true
	case 1787:
		return "funk-license", true
	case 1788:
		return "psmond", true
	case 1789:
		return "hello", true
	case 1790:
		return "nmsp", true
	case 1791:
		return "ea1", true
	case 1792:
		return "ibm-dt-2", true
	case 1793:
		return "rsc-robot", true
	case 1794:
		return "cera-bcm", true
	case 1795:
		return "dpi-proxy", true
	case 1796:
		return "vocaltec-admin", true
	case 1797:
		return "uma", true
	case 1798:
		return "etp", true
	case 1799:
		return "netrisk", true
	case 1800:
		return "ansys-lm", true
	case 1801:
		return "msmq", true
	case 1802:
		return "concomp1", true
	case 1803:
		return "hp-hcip-gwy", true
	case 1804:
		return "enl", true
	case 1805:
		return "enl-name", true
	case 1806:
		return "musiconline", true
	case 1807:
		return "fhsp", true
	case 1808:
		return "oracle-vp2", true
	case 1809:
		return "oracle-vp1", true
	case 1810:
		return "jerand-lm", true
	case 1811:
		return "scientia-sdb", true
	case 1812:
		return "radius", true
	case 1813:
		return "radius-acct", true
	case 1814:
		return "tdp-suite", true
	case 1815:
		return "mmpft", true
	case 1816:
		return "harp", true
	case 1817:
		return "rkb-oscs", true
	case 1818:
		return "etftp", true
	case 1819:
		return "plato-lm", true
	case 1820:
		return "mcagent", true
	case 1821:
		return "donnyworld", true
	case 1822:
		return "es-elmd", true
	case 1823:
		return "unisys-lm", true
	case 1824:
		return "metrics-pas", true
	case 1825:
		return "direcpc-video", true
	case 1826:
		return "ardt", true
	case 1827:
		return "asi", true
	case 1828:
		return "itm-mcell-u", true
	case 1829:
		return "optika-emedia", true
	case 1830:
		return "net8-cman", true
	case 1831:
		return "myrtle", true
	case 1832:
		return "tht-treasure", true
	case 1833:
		return "udpradio", true
	case 1834:
		return "ardusuni", true
	case 1835:
		return "ardusmul", true
	case 1836:
		return "ste-smsc", true
	case 1837:
		return "csoft1", true
	case 1838:
		return "talnet", true
	case 1839:
		return "netopia-vo1", true
	case 1840:
		return "netopia-vo2", true
	case 1841:
		return "netopia-vo3", true
	case 1842:
		return "netopia-vo4", true
	case 1843:
		return "netopia-vo5", true
	case 1844:
		return "direcpc-dll", true
	case 1845:
		return "altalink", true
	case 1846:
		return "tunstall-pnc", true
	case 1847:
		return "slp-notify", true
	case 1848:
		return "fjdocdist", true
	case 1849:
		return "alpha-sms", true
	case 1850:
		return "gsi", true
	case 1851:
		return "ctcd", true
	case 1852:
		return "virtual-time", true
	case 1853:
		return "vids-avtp", true
	case 1854:
		return "buddy-draw", true
	case 1855:
		return "fiorano-rtrsvc", true
	case 1856:
		return "fiorano-msgsvc", true
	case 1857:
		return "datacaptor", true
	case 1858:
		return "privateark", true
	case 1859:
		return "gammafetchsvr", true
	case 1860:
		return "sunscalar-svc", true
	case 1861:
		return "lecroy-vicp", true
	case 1862:
		return "mysql-cm-agent", true
	case 1863:
		return "msnp", true
	case 1864:
		return "paradym-31port", true
	case 1865:
		return "entp", true
	case 1866:
		return "swrmi", true
	case 1867:
		return "udrive", true
	case 1868:
		return "viziblebrowser", true
	case 1869:
		return "transact", true
	case 1870:
		return "sunscalar-dns", true
	case 1871:
		return "canocentral0", true
	case 1872:
		return "canocentral1", true
	case 1873:
		return "fjmpjps", true
	case 1874:
		return "fjswapsnp", true
	case 1875:
		return "westell-stats", true
	case 1876:
		return "ewcappsrv", true
	case 1877:
		return "hp-webqosdb", true
	case 1878:
		return "drmsmc", true
	case 1879:
		return "nettgain-nms", true
	case 1880:
		return "vsat-control", true
	case 1881:
		return "ibm-mqseries2", true
	case 1882:
		return "ecsqdmn", true
	case 1883:
		return "mqtt", true
	case 1884:
		return "idmaps", true
	case 1885:
		return "vrtstrapserver", true
	case 1886:
		return "leoip", true
	case 1887:
		return "filex-lport", true
	case 1888:
		return "ncconfig", true
	case 1889:
		return "unify-adapter", true
	case 1890:
		return "wilkenlistener", true
	case 1891:
		return "childkey-notif", true
	case 1892:
		return "childkey-ctrl", true
	case 1893:
		return "elad", true
	case 1894:
		return "o2server-port", true
	case 1896:
		return "b-novative-ls", true
	case 1897:
		return "metaagent", true
	case 1898:
		return "cymtec-port", true
	case 1899:
		return "mc2studios", true
	case 1900:
		return "ssdp", true
	case 1901:
		return "fjicl-tep-a", true
	case 1902:
		return "fjicl-tep-b", true
	case 1903:
		return "linkname", true
	case 1904:
		return "fjicl-tep-c", true
	case 1905:
		return "sugp", true
	case 1906:
		return "tpmd", true
	case 1907:
		return "intrastar", true
	case 1908:
		return "dawn", true
	case 1909:
		return "global-wlink", true
	case 1910:
		return "ultrabac", true
	case 1911:
		return "mtp", true
	case 1912:
		return "rhp-iibp", true
	case 1913:
		return "armadp", true
	case 1914:
		return "elm-momentum", true
	case 1915:
		return "facelink", true
	case 1916:
		return "persona", true
	case 1917:
		return "noagent", true
	case 1918:
		return "can-nds", true
	case 1919:
		return "can-dch", true
	case 1920:
		return "can-ferret", true
	case 1921:
		return "noadmin", true
	case 1922:
		return "tapestry", true
	case 1923:
		return "spice", true
	case 1924:
		return "xiip", true
	case 1925:
		return "discovery-port", true
	case 1926:
		return "egs", true
	case 1927:
		return "videte-cipc", true
	case 1928:
		return "emsd-port", true
	case 1929:
		return "bandwiz-system", true
	case 1930:
		return "driveappserver", true
	case 1931:
		return "amdsched", true
	case 1932:
		return "ctt-broker", true
	case 1933:
		return "xmapi", true
	case 1934:
		return "xaapi", true
	case 1935:
		return "macromedia-fcs", true
	case 1936:
		return "jetcmeserver", true
	case 1937:
		return "jwserver", true
	case 1938:
		return "jwclient", true
	case 1939:
		return "jvserver", true
	case 1940:
		return "jvclient", true
	case 1941:
		return "dic-aida", true
	case 1942:
		return "res", true
	case 1943:
		return "beeyond-media", true
	case 1944:
		return "close-combat", true
	case 1945:
		return "dialogic-elmd", true
	case 1946:
		return "tekpls", true
	case 1947:
		return "sentinelsrm", true
	case 1948:
		return "eye2eye", true
	case 1949:
		return "ismaeasdaqlive", true
	case 1950:
		return "ismaeasdaqtest", true
	case 1951:
		return "bcs-lmserver", true
	case 1952:
		return "mpnjsc", true
	case 1953:
		return "rapidbase", true
	case 1954:
		return "abr-api", true
	case 1955:
		return "abr-secure", true
	case 1956:
		return "vrtl-vmf-ds", true
	case 1957:
		return "unix-status", true
	case 1958:
		return "dxadmind", true
	case 1959:
		return "simp-all", true
	case 1960:
		return "nasmanager", true
	case 1961:
		return "bts-appserver", true
	case 1962:
		return "biap-mp", true
	case 1963:
		return "webmachine", true
	case 1964:
		return "solid-e-engine", true
	case 1965:
		return "tivoli-npm", true
	case 1966:
		return "slush", true
	case 1967:
		return "sns-quote", true
	case 1968:
		return "lipsinc", true
	case 1969:
		return "lipsinc1", true
	case 1970:
		return "netop-rc", true
	case 1971:
		return "netop-school", true
	case 1972:
		return "intersys-cache", true
	case 1973:
		return "dlsrap", true
	case 1974:
		return "drp", true
	case 1975:
		return "tcoflashagent", true
	case 1976:
		return "tcoregagent", true
	case 1977:
		return "tcoaddressbook", true
	case 1978:
		return "unisql", true
	case 1979:
		return "unisql-java", true
	case 1980:
		return "pearldoc-xact", true
	case 1981:
		return "p2pq", true
	case 1982:
		return "estamp", true
	case 1983:
		return "lhtp", true
	case 1984:
		return "bb", true
	case 1985:
		return "hsrp", true
	case 1986:
		return "licensedaemon", true
	case 1987:
		return "tr-rsrb-p1", true
	case 1988:
		return "tr-rsrb-p2", true
	case 1989:
		return "tr-rsrb-p3", true
	case 1990:
		return "stun-p1", true
	case 1991:
		return "stun-p2", true
	case 1992:
		return "stun-p3", true
	case 1993:
		return "snmp-tcp-port", true
	case 1994:
		return "stun-port", true
	case 1995:
		return "perf-port", true
	case 1996:
		return "tr-rsrb-port", true
	case 1997:
		return "gdp-port", true
	case 1998:
		return "x25-svc-port", true
	case 1999:
		return "tcp-id-port", true
	case 2000:
		return "cisco-sccp", true
	case 2001:
		return "wizard", true
	case 2002:
		return "globe", true
	case 2003:
		return "brutus", true
	case 2004:
		return "emce", true
	case 2005:
		return "oracle", true
	case 2006:
		return "raid-cd", true
	case 2007:
		return "raid-am", true
	case 2008:
		return "terminaldb", true
	case 2009:
		return "whosockami", true
	case 2010:
		return "pipe-server", true
	case 2011:
		return "servserv", true
	case 2012:
		return "raid-ac", true
	case 2013:
		return "raid-cd", true
	case 2014:
		return "raid-sf", true
	case 2015:
		return "raid-cs", true
	case 2016:
		return "bootserver", true
	case 2017:
		return "bootclient", true
	case 2018:
		return "rellpack", true
	case 2019:
		return "about", true
	case 2020:
		return "xinupageserver", true
	case 2021:
		return "xinuexpansion1", true
	case 2022:
		return "xinuexpansion2", true
	case 2023:
		return "xinuexpansion3", true
	case 2024:
		return "xinuexpansion4", true
	case 2025:
		return "xribs", true
	case 2026:
		return "scrabble", true
	case 2027:
		return "shadowserver", true
	case 2028:
		return "submitserver", true
	case 2029:
		return "hsrpv6", true
	case 2030:
		return "device2", true
	case 2031:
		return "mobrien-chat", true
	case 2032:
		return "blackboard", true
	case 2033:
		return "glogger", true
	case 2034:
		return "scoremgr", true
	case 2035:
		return "imsldoc", true
	case 2036:
		return "e-dpnet", true
	case 2037:
		return "applus", true
	case 2038:
		return "objectmanager", true
	case 2039:
		return "prizma", true
	case 2040:
		return "lam", true
	case 2041:
		return "interbase", true
	case 2042:
		return "isis", true
	case 2043:
		return "isis-bcast", true
	case 2044:
		return "rimsl", true
	case 2045:
		return "cdfunc", true
	case 2046:
		return "sdfunc", true
	case 2047:
		return "dls", true
	case 2048:
		return "dls-monitor", true
	case 2049:
		return "shilp", true
	case 2050:
		return "av-emb-config", true
	case 2051:
		return "epnsdp", true
	case 2052:
		return "clearvisn", true
	case 2053:
		return "lot105-ds-upd", true
	case 2054:
		return "weblogin", true
	case 2055:
		return "iop", true
	case 2056:
		return "omnisky", true
	case 2057:
		return "rich-cp", true
	case 2058:
		return "newwavesearch", true
	case 2059:
		return "bmc-messaging", true
	case 2060:
		return "teleniumdaemon", true
	case 2061:
		return "netmount", true
	case 2062:
		return "icg-swp", true
	case 2063:
		return "icg-bridge", true
	case 2064:
		return "icg-iprelay", true
	case 2065:
		return "dlsrpn", true
	case 2066:
		return "aura", true
	case 2067:
		return "dlswpn", true
	case 2068:
		return "avauthsrvprtcl", true
	case 2069:
		return "event-port", true
	case 2070:
		return "ah-esp-encap", true
	case 2071:
		return "acp-port", true
	case 2072:
		return "msync", true
	case 2073:
		return "gxs-data-port", true
	case 2074:
		return "vrtl-vmf-sa", true
	case 2075:
		return "newlixengine", true
	case 2076:
		return "newlixconfig", true
	case 2077:
		return "tsrmagt", true
	case 2078:
		return "tpcsrvr", true
	case 2079:
		return "idware-router", true
	case 2080:
		return "autodesk-nlm", true
	case 2081:
		return "kme-trap-port", true
	case 2082:
		return "infowave", true
	case 2083:
		return "radsec", true
	case 2084:
		return "sunclustergeo", true
	case 2085:
		return "ada-cip", true
	case 2086:
		return "gnunet", true
	case 2087:
		return "eli", true
	case 2088:
		return "ip-blf", true
	case 2089:
		return "sep", true
	case 2090:
		return "lrp", true
	case 2091:
		return "prp", true
	case 2092:
		return "descent3", true
	case 2093:
		return "nbx-cc", true
	case 2094:
		return "nbx-au", true
	case 2095:
		return "nbx-ser", true
	case 2096:
		return "nbx-dir", true
	case 2097:
		return "jetformpreview", true
	case 2098:
		return "dialog-port", true
	case 2099:
		return "h2250-annex-g", true
	case 2100:
		return "amiganetfs", true
	case 2101:
		return "rtcm-sc104", true
	case 2102:
		return "zephyr-srv", true
	case 2103:
		return "zephyr-clt", true
	case 2104:
		return "zephyr-hm", true
	case 2105:
		return "minipay", true
	case 2106:
		return "mzap", true
	case 2107:
		return "bintec-admin", true
	case 2108:
		return "comcam", true
	case 2109:
		return "ergolight", true
	case 2110:
		return "umsp", true
	case 2111:
		return "dsatp", true
	case 2112:
		return "idonix-metanet", true
	case 2113:
		return "hsl-storm", true
	case 2114:
		return "ariascribe", true
	case 2115:
		return "kdm", true
	case 2116:
		return "ccowcmr", true
	case 2117:
		return "mentaclient", true
	case 2118:
		return "mentaserver", true
	case 2119:
		return "gsigatekeeper", true
	case 2120:
		return "qencp", true
	case 2121:
		return "scientia-ssdb", true
	case 2122:
		return "caupc-remote", true
	case 2123:
		return "gtp-control", true
	case 2124:
		return "elatelink", true
	case 2125:
		return "lockstep", true
	case 2126:
		return "pktcable-cops", true
	case 2127:
		return "index-pc-wb", true
	case 2128:
		return "net-steward", true
	case 2129:
		return "cs-live", true
	case 2130:
		return "xds", true
	case 2131:
		return "avantageb2b", true
	case 2132:
		return "solera-epmap", true
	case 2133:
		return "zymed-zpp", true
	case 2134:
		return "avenue", true
	case 2135:
		return "gris", true
	case 2136:
		return "appworxsrv", true
	case 2137:
		return "connect", true
	case 2138:
		return "unbind-cluster", true
	case 2139:
		return "ias-auth", true
	case 2140:
		return "ias-reg", true
	case 2141:
		return "ias-admind", true
	case 2142:
		return "tdmoip", true
	case 2143:
		return "lv-jc", true
	case 2144:
		return "lv-ffx", true
	case 2145:
		return "lv-pici", true
	case 2146:
		return "lv-not", true
	case 2147:
		return "lv-auth", true
	case 2148:
		return "veritas-ucl", true
	case 2149:
		return "acptsys", true
	case 2150:
		return "dynamic3d", true
	case 2151:
		return "docent", true
	case 2152:
		return "gtp-user", true
	case 2153:
		return "ctlptc", true
	case 2154:
		return "stdptc", true
	case 2155:
		return "brdptc", true
	case 2156:
		return "trp", true
	case 2157:
		return "xnds", true
	case 2158:
		return "touchnetplus", true
	case 2159:
		return "gdbremote", true
	case 2160:
		return "apc-2160", true
	case 2161:
		return "apc-2161", true
	case 2162:
		return "navisphere", true
	case 2163:
		return "navisphere-sec", true
	case 2164:
		return "ddns-v3", true
	case 2165:
		return "x-bone-api", true
	case 2166:
		return "iwserver", true
	case 2167:
		return "raw-serial", true
	case 2168:
		return "easy-soft-mux", true
	case 2169:
		return "brain", true
	case 2170:
		return "eyetv", true
	case 2171:
		return "msfw-storage", true
	case 2172:
		return "msfw-s-storage", true
	case 2173:
		return "msfw-replica", true
	case 2174:
		return "msfw-array", true
	case 2175:
		return "airsync", true
	case 2176:
		return "rapi", true
	case 2177:
		return "qwave", true
	case 2178:
		return "bitspeer", true
	case 2179:
		return "vmrdp", true
	case 2180:
		return "mc-gt-srv", true
	case 2181:
		return "eforward", true
	case 2182:
		return "cgn-stat", true
	case 2183:
		return "cgn-config", true
	case 2184:
		return "nvd", true
	case 2185:
		return "onbase-dds", true
	case 2186:
		return "gtaua", true
	case 2187:
		return "ssmd", true
	case 2190:
		return "tivoconnect", true
	case 2191:
		return "tvbus", true
	case 2192:
		return "asdis", true
	case 2193:
		return "drwcs", true
	case 2197:
		return "mnp-exchange", true
	case 2198:
		return "onehome-remote", true
	case 2199:
		return "onehome-help", true
	case 2201:
		return "ats", true
	case 2202:
		return "imtc-map", true
	case 2203:
		return "b2-runtime", true
	case 2204:
		return "b2-license", true
	case 2205:
		return "jps", true
	case 2206:
		return "hpocbus", true
	case 2207:
		return "hpssd", true
	case 2208:
		return "hpiod", true
	case 2209:
		return "rimf-ps", true
	case 2210:
		return "noaaport", true
	case 2211:
		return "emwin", true
	case 2212:
		return "leecoposserver", true
	case 2213:
		return "kali", true
	case 2214:
		return "rpi", true
	case 2215:
		return "ipcore", true
	case 2216:
		return "vtu-comms", true
	case 2217:
		return "gotodevice", true
	case 2218:
		return "bounzza", true
	case 2219:
		return "netiq-ncap", true
	case 2220:
		return "netiq", true
	case 2221:
		return "ethernet-ip-s", true
	case 2222:
		return "EtherNet-IP-1", true
	case 2223:
		return "rockwell-csp2", true
	case 2224:
		return "efi-mg", true
	case 2226:
		return "di-drm", true
	case 2227:
		return "di-msg", true
	case 2228:
		return "ehome-ms", true
	case 2229:
		return "datalens", true
	case 2230:
		return "queueadm", true
	case 2231:
		return "wimaxasncp", true
	case 2232:
		return "ivs-video", true
	case 2233:
		return "infocrypt", true
	case 2234:
		return "directplay", true
	case 2235:
		return "sercomm-wlink", true
	case 2236:
		return "nani", true
	case 2237:
		return "optech-port1-lm", true
	case 2238:
		return "aviva-sna", true
	case 2239:
		return "imagequery", true
	case 2240:
		return "recipe", true
	case 2241:
		return "ivsd", true
	case 2242:
		return "foliocorp", true
	case 2243:
		return "magicom", true
	case 2244:
		return "nmsserver", true
	case 2245:
		return "hao", true
	case 2246:
		return "pc-mta-addrmap", true
	case 2247:
		return "antidotemgrsvr", true
	case 2248:
		return "ums", true
	case 2249:
		return "rfmp", true
	case 2250:
		return "remote-collab", true
	case 2251:
		return "dif-port", true
	case 2252:
		return "njenet-ssl", true
	case 2253:
		return "dtv-chan-req", true
	case 2254:
		return "seispoc", true
	case 2255:
		return "vrtp", true
	case 2256:
		return "pcc-mfp", true
	case 2257:
		return "simple-tx-rx", true
	case 2258:
		return "rcts", true
	case 2259:
		return "bid-serv", true
	case 2260:
		return "apc-2260", true
	case 2261:
		return "comotionmaster", true
	case 2262:
		return "comotionback", true
	case 2263:
		return "ecwcfg", true
	case 2264:
		return "apx500api-1", true
	case 2265:
		return "apx500api-2", true
	case 2266:
		return "mfserver", true
	case 2267:
		return "ontobroker", true
	case 2268:
		return "amt", true
	case 2269:
		return "mikey", true
	case 2270:
		return "starschool", true
	case 2271:
		return "mmcals", true
	case 2272:
		return "mmcal", true
	case 2273:
		return "mysql-im", true
	case 2274:
		return "pcttunnell", true
	case 2275:
		return "ibridge-data", true
	case 2276:
		return "ibridge-mgmt", true
	case 2277:
		return "bluectrlproxy", true
	case 2278:
		return "s3db", true
	case 2279:
		return "xmquery", true
	case 2280:
		return "lnvpoller", true
	case 2281:
		return "lnvconsole", true
	case 2282:
		return "lnvalarm", true
	case 2283:
		return "lnvstatus", true
	case 2284:
		return "lnvmaps", true
	case 2285:
		return "lnvmailmon", true
	case 2286:
		return "nas-metering", true
	case 2287:
		return "dna", true
	case 2288:
		return "netml", true
	case 2289:
		return "dict-lookup", true
	case 2290:
		return "sonus-logging", true
	case 2291:
		return "eapsp", true
	case 2292:
		return "mib-streaming", true
	case 2293:
		return "npdbgmngr", true
	case 2294:
		return "konshus-lm", true
	case 2295:
		return "advant-lm", true
	case 2296:
		return "theta-lm", true
	case 2297:
		return "d2k-datamover1", true
	case 2298:
		return "d2k-datamover2", true
	case 2299:
		return "pc-telecommute", true
	case 2300:
		return "cvmmon", true
	case 2301:
		return "cpq-wbem", true
	case 2302:
		return "binderysupport", true
	case 2303:
		return "proxy-gateway", true
	case 2304:
		return "attachmate-uts", true
	case 2305:
		return "mt-scaleserver", true
	case 2306:
		return "tappi-boxnet", true
	case 2307:
		return "pehelp", true
	case 2308:
		return "sdhelp", true
	case 2309:
		return "sdserver", true
	case 2310:
		return "sdclient", true
	case 2311:
		return "messageservice", true
	case 2312:
		return "wanscaler", true
	case 2313:
		return "iapp", true
	case 2314:
		return "cr-websystems", true
	case 2315:
		return "precise-sft", true
	case 2316:
		return "sent-lm", true
	case 2317:
		return "attachmate-g32", true
	case 2318:
		return "cadencecontrol", true
	case 2319:
		return "infolibria", true
	case 2320:
		return "siebel-ns", true
	case 2321:
		return "rdlap", true
	case 2322:
		return "ofsd", true
	case 2323:
		return "3d-nfsd", true
	case 2324:
		return "cosmocall", true
	case 2325:
		return "ansysli", true
	case 2326:
		return "idcp", true
	case 2327:
		return "xingcsm", true
	case 2328:
		return "netrix-sftm", true
	case 2329:
		return "nvd", true
	case 2330:
		return "tscchat", true
	case 2331:
		return "agentview", true
	case 2332:
		return "rcc-host", true
	case 2333:
		return "snapp", true
	case 2334:
		return "ace-client", true
	case 2335:
		return "ace-proxy", true
	case 2336:
		return "appleugcontrol", true
	case 2337:
		return "ideesrv", true
	case 2338:
		return "norton-lambert", true
	case 2339:
		return "3com-webview", true
	case 2340:
		return "wrs-registry", true
	case 2341:
		return "xiostatus", true
	case 2342:
		return "manage-exec", true
	case 2343:
		return "nati-logos", true
	case 2344:
		return "fcmsys", true
	case 2345:
		return "dbm", true
	case 2346:
		return "redstorm-join", true
	case 2347:
		return "redstorm-find", true
	case 2348:
		return "redstorm-info", true
	case 2349:
		return "redstorm-diag", true
	case 2350:
		return "psbserver", true
	case 2351:
		return "psrserver", true
	case 2352:
		return "pslserver", true
	case 2353:
		return "pspserver", true
	case 2354:
		return "psprserver", true
	case 2355:
		return "psdbserver", true
	case 2356:
		return "gxtelmd", true
	case 2357:
		return "unihub-server", true
	case 2358:
		return "futrix", true
	case 2359:
		return "flukeserver", true
	case 2360:
		return "nexstorindltd", true
	case 2361:
		return "tl1", true
	case 2362:
		return "digiman", true
	case 2363:
		return "mediacntrlnfsd", true
	case 2364:
		return "oi-2000", true
	case 2365:
		return "dbref", true
	case 2366:
		return "qip-login", true
	case 2367:
		return "service-ctrl", true
	case 2368:
		return "opentable", true
	case 2369:
		return "bif-p2p", true
	case 2370:
		return "l3-hbmon", true
	case 2372:
		return "lanmessenger", true
	case 2378:
		return "dali", true
	case 2381:
		return "compaq-https", true
	case 2382:
		return "ms-olap3", true
	case 2383:
		return "ms-olap4", true
	case 2384:
		return "sd-capacity", true
	case 2385:
		return "sd-data", true
	case 2386:
		return "virtualtape", true
	case 2387:
		return "vsamredirector", true
	case 2388:
		return "mynahautostart", true
	case 2389:
		return "ovsessionmgr", true
	case 2390:
		return "rsmtp", true
	case 2391:
		return "3com-net-mgmt", true
	case 2392:
		return "tacticalauth", true
	case 2393:
		return "ms-olap1", true
	case 2394:
		return "ms-olap2", true
	case 2395:
		return "lan900-remote", true
	case 2396:
		return "wusage", true
	case 2397:
		return "ncl", true
	case 2398:
		return "orbiter", true
	case 2399:
		return "fmpro-fdal", true
	case 2400:
		return "opequus-server", true
	case 2401:
		return "cvspserver", true
	case 2402:
		return "taskmaster2000", true
	case 2403:
		return "taskmaster2000", true
	case 2404:
		return "iec-104", true
	case 2405:
		return "trc-netpoll", true
	case 2406:
		return "jediserver", true
	case 2407:
		return "orion", true
	case 2409:
		return "sns-protocol", true
	case 2410:
		return "vrts-registry", true
	case 2411:
		return "netwave-ap-mgmt", true
	case 2412:
		return "cdn", true
	case 2413:
		return "orion-rmi-reg", true
	case 2414:
		return "beeyond", true
	case 2415:
		return "codima-rtp", true
	case 2416:
		return "rmtserver", true
	case 2417:
		return "composit-server", true
	case 2418:
		return "cas", true
	case 2419:
		return "attachmate-s2s", true
	case 2420:
		return "dslremote-mgmt", true
	case 2421:
		return "g-talk", true
	case 2422:
		return "crmsbits", true
	case 2423:
		return "rnrp", true
	case 2424:
		return "kofax-svr", true
	case 2425:
		return "fjitsuappmgr", true
	case 2426:
		return "vcmp", true
	case 2427:
		return "mgcp-gateway", true
	case 2428:
		return "ott", true
	case 2429:
		return "ft-role", true
	case 2430:
		return "venus", true
	case 2431:
		return "venus-se", true
	case 2432:
		return "codasrv", true
	case 2433:
		return "codasrv-se", true
	case 2434:
		return "pxc-epmap", true
	case 2435:
		return "optilogic", true
	case 2436:
		return "topx", true
	case 2437:
		return "unicontrol", true
	case 2438:
		return "msp", true
	case 2439:
		return "sybasedbsynch", true
	case 2440:
		return "spearway", true
	case 2441:
		return "pvsw-inet", true
	case 2442:
		return "netangel", true
	case 2443:
		return "powerclientcsf", true
	case 2444:
		return "btpp2sectrans", true
	case 2445:
		return "dtn1", true
	case 2446:
		return "bues-service", true
	case 2447:
		return "ovwdb", true
	case 2448:
		return "hpppssvr", true
	case 2449:
		return "ratl", true
	case 2450:
		return "netadmin", true
	case 2451:
		return "netchat", true
	case 2452:
		return "snifferclient", true
	case 2453:
		return "madge-ltd", true
	case 2454:
		return "indx-dds", true
	case 2455:
		return "wago-io-system", true
	case 2456:
		return "altav-remmgt", true
	case 2457:
		return "rapido-ip", true
	case 2458:
		return "griffin", true
	case 2459:
		return "xrpl", true
	case 2460:
		return "ms-theater", true
	case 2461:
		return "qadmifoper", true
	case 2462:
		return "qadmifevent", true
	case 2463:
		return "lsi-raid-mgmt", true
	case 2464:
		return "direcpc-si", true
	case 2465:
		return "lbm", true
	case 2466:
		return "lbf", true
	case 2467:
		return "high-criteria", true
	case 2468:
		return "qip-msgd", true
	case 2469:
		return "mti-tcs-comm", true
	case 2470:
		return "taskman-port", true
	case 2471:
		return "seaodbc", true
	case 2472:
		return "c3", true
	case 2473:
		return "aker-cdp", true
	case 2474:
		return "vitalanalysis", true
	case 2475:
		return "ace-server", true
	case 2476:
		return "ace-svr-prop", true
	case 2477:
		return "ssm-cvs", true
	case 2478:
		return "ssm-cssps", true
	case 2479:
		return "ssm-els", true
	case 2480:
		return "powerexchange", true
	case 2481:
		return "giop", true
	case 2482:
		return "giop-ssl", true
	case 2483:
		return "ttc", true
	case 2484:
		return "ttc-ssl", true
	case 2485:
		return "netobjects1", true
	case 2486:
		return "netobjects2", true
	case 2487:
		return "pns", true
	case 2488:
		return "moy-corp", true
	case 2489:
		return "tsilb", true
	case 2490:
		return "qip-qdhcp", true
	case 2491:
		return "conclave-cpp", true
	case 2492:
		return "groove", true
	case 2493:
		return "talarian-mqs", true
	case 2494:
		return "bmc-ar", true
	case 2495:
		return "fast-rem-serv", true
	case 2496:
		return "dirgis", true
	case 2497:
		return "quaddb", true
	case 2498:
		return "odn-castraq", true
	case 2499:
		return "unicontrol", true
	case 2500:
		return "rtsserv", true
	case 2501:
		return "rtsclient", true
	case 2502:
		return "kentrox-prot", true
	case 2503:
		return "nms-dpnss", true
	case 2504:
		return "wlbs", true
	case 2505:
		return "ppcontrol", true
	case 2506:
		return "jbroker", true
	case 2507:
		return "spock", true
	case 2508:
		return "jdatastore", true
	case 2509:
		return "fjmpss", true
	case 2510:
		return "fjappmgrbulk", true
	case 2511:
		return "metastorm", true
	case 2512:
		return "citrixima", true
	case 2513:
		return "citrixadmin", true
	case 2514:
		return "facsys-ntp", true
	case 2515:
		return "facsys-router", true
	case 2516:
		return "maincontrol", true
	case 2517:
		return "call-sig-trans", true
	case 2518:
		return "willy", true
	case 2519:
		return "globmsgsvc", true
	case 2520:
		return "pvsw", true
	case 2521:
		return "adaptecmgr", true
	case 2522:
		return "windb", true
	case 2523:
		return "qke-llc-v3", true
	case 2524:
		return "optiwave-lm", true
	case 2525:
		return "ms-v-worlds", true
	case 2526:
		return "ema-sent-lm", true
	case 2527:
		return "iqserver", true
	case 2528:
		return "ncr-ccl", true
	case 2529:
		return "utsftp", true
	case 2530:
		return "vrcommerce", true
	case 2531:
		return "ito-e-gui", true
	case 2532:
		return "ovtopmd", true
	case 2533:
		return "snifferserver", true
	case 2534:
		return "combox-web-acc", true
	case 2535:
		return "madcap", true
	case 2536:
		return "btpp2audctr1", true
	case 2537:
		return "upgrade", true
	case 2538:
		return "vnwk-prapi", true
	case 2539:
		return "vsiadmin", true
	case 2540:
		return "lonworks", true
	case 2541:
		return "lonworks2", true
	case 2542:
		return "udrawgraph", true
	case 2543:
		return "reftek", true
	case 2544:
		return "novell-zen", true
	case 2545:
		return "sis-emt", true
	case 2546:
		return "vytalvaultbrtp", true
	case 2547:
		return "vytalvaultvsmp", true
	case 2548:
		return "vytalvaultpipe", true
	case 2549:
		return "ipass", true
	case 2550:
		return "ads", true
	case 2551:
		return "isg-uda-server", true
	case 2552:
		return "call-logging", true
	case 2553:
		return "efidiningport", true
	case 2554:
		return "vcnet-link-v10", true
	case 2555:
		return "compaq-wcp", true
	case 2556:
		return "nicetec-nmsvc", true
	case 2557:
		return "nicetec-mgmt", true
	case 2558:
		return "pclemultimedia", true
	case 2559:
		return "lstp", true
	case 2560:
		return "labrat", true
	case 2561:
		return "mosaixcc", true
	case 2562:
		return "delibo", true
	case 2563:
		return "cti-redwood", true
	case 2564:
		return "hp-3000-telnet", true
	case 2565:
		return "coord-svr", true
	case 2566:
		return "pcs-pcw", true
	case 2567:
		return "clp", true
	case 2568:
		return "spamtrap", true
	case 2569:
		return "sonuscallsig", true
	case 2570:
		return "hs-port", true
	case 2571:
		return "cecsvc", true
	case 2572:
		return "ibp", true
	case 2573:
		return "trustestablish", true
	case 2574:
		return "blockade-bpsp", true
	case 2575:
		return "hl7", true
	case 2576:
		return "tclprodebugger", true
	case 2577:
		return "scipticslsrvr", true
	case 2578:
		return "rvs-isdn-dcp", true
	case 2579:
		return "mpfoncl", true
	case 2580:
		return "tributary", true
	case 2581:
		return "argis-te", true
	case 2582:
		return "argis-ds", true
	case 2583:
		return "mon", true
	case 2584:
		return "cyaserv", true
	case 2585:
		return "netx-server", true
	case 2586:
		return "netx-agent", true
	case 2587:
		return "masc", true
	case 2588:
		return "privilege", true
	case 2589:
		return "quartus-tcl", true
	case 2590:
		return "idotdist", true
	case 2591:
		return "maytagshuffle", true
	case 2592:
		return "netrek", true
	case 2593:
		return "mns-mail", true
	case 2594:
		return "dts", true
	case 2595:
		return "worldfusion1", true
	case 2596:
		return "worldfusion2", true
	case 2597:
		return "homesteadglory", true
	case 2598:
		return "citriximaclient", true
	case 2599:
		return "snapd", true
	case 2600:
		return "hpstgmgr", true
	case 2601:
		return "discp-client", true
	case 2602:
		return "discp-server", true
	case 2603:
		return "servicemeter", true
	case 2604:
		return "nsc-ccs", true
	case 2605:
		return "nsc-posa", true
	case 2606:
		return "netmon", true
	case 2607:
		return "connection", true
	case 2608:
		return "wag-service", true
	case 2609:
		return "system-monitor", true
	case 2610:
		return "versa-tek", true
	case 2611:
		return "lionhead", true
	case 2612:
		return "qpasa-agent", true
	case 2613:
		return "smntubootstrap", true
	case 2614:
		return "neveroffline", true
	case 2615:
		return "firepower", true
	case 2616:
		return "appswitch-emp", true
	case 2617:
		return "cmadmin", true
	case 2618:
		return "priority-e-com", true
	case 2619:
		return "bruce", true
	case 2620:
		return "lpsrecommender", true
	case 2621:
		return "miles-apart", true
	case 2622:
		return "metricadbc", true
	case 2623:
		return "lmdp", true
	case 2624:
		return "aria", true
	case 2625:
		return "blwnkl-port", true
	case 2626:
		return "gbjd816", true
	case 2627:
		return "moshebeeri", true
	case 2628:
		return "dict", true
	case 2629:
		return "sitaraserver", true
	case 2630:
		return "sitaramgmt", true
	case 2631:
		return "sitaradir", true
	case 2632:
		return "irdg-post", true
	case 2633:
		return "interintelli", true
	case 2634:
		return "pk-electronics", true
	case 2635:
		return "backburner", true
	case 2636:
		return "solve", true
	case 2637:
		return "imdocsvc", true
	case 2638:
		return "sybaseanywhere", true
	case 2639:
		return "aminet", true
	case 2640:
		return "ami-control", true
	case 2641:
		return "hdl-srv", true
	case 2642:
		return "tragic", true
	case 2643:
		return "gte-samp", true
	case 2644:
		return "travsoft-ipx-t", true
	case 2645:
		return "novell-ipx-cmd", true
	case 2646:
		return "and-lm", true
	case 2647:
		return "syncserver", true
	case 2648:
		return "upsnotifyprot", true
	case 2649:
		return "vpsipport", true
	case 2650:
		return "eristwoguns", true
	case 2651:
		return "ebinsite", true
	case 2652:
		return "interpathpanel", true
	case 2653:
		return "sonus", true
	case 2654:
		return "corel-vncadmin", true
	case 2655:
		return "unglue", true
	case 2656:
		return "kana", true
	case 2657:
		return "sns-dispatcher", true
	case 2658:
		return "sns-admin", true
	case 2659:
		return "sns-query", true
	case 2660:
		return "gcmonitor", true
	case 2661:
		return "olhost", true
	case 2662:
		return "bintec-capi", true
	case 2663:
		return "bintec-tapi", true
	case 2664:
		return "patrol-mq-gm", true
	case 2665:
		return "patrol-mq-nm", true
	case 2666:
		return "extensis", true
	case 2667:
		return "alarm-clock-s", true
	case 2668:
		return "alarm-clock-c", true
	case 2669:
		return "toad", true
	case 2670:
		return "tve-announce", true
	case 2671:
		return "newlixreg", true
	case 2672:
		return "nhserver", true
	case 2673:
		return "firstcall42", true
	case 2674:
		return "ewnn", true
	case 2675:
		return "ttc-etap", true
	case 2676:
		return "simslink", true
	case 2677:
		return "gadgetgate1way", true
	case 2678:
		return "gadgetgate2way", true
	case 2679:
		return "syncserverssl", true
	case 2680:
		return "pxc-sapxom", true
	case 2681:
		return "mpnjsomb", true
	case 2683:
		return "ncdloadbalance", true
	case 2684:
		return "mpnjsosv", true
	case 2685:
		return "mpnjsocl", true
	case 2686:
		return "mpnjsomg", true
	case 2687:
		return "pq-lic-mgmt", true
	case 2688:
		return "md-cg-http", true
	case 2689:
		return "fastlynx", true
	case 2690:
		return "hp-nnm-data", true
	case 2691:
		return "itinternet", true
	case 2692:
		return "admins-lms", true
	case 2694:
		return "pwrsevent", true
	case 2695:
		return "vspread", true
	case 2696:
		return "unifyadmin", true
	case 2697:
		return "oce-snmp-trap", true
	case 2698:
		return "mck-ivpip", true
	case 2699:
		return "csoft-plusclnt", true
	case 2700:
		return "tqdata", true
	case 2701:
		return "sms-rcinfo", true
	case 2702:
		return "sms-xfer", true
	case 2703:
		return "sms-chat", true
	case 2704:
		return "sms-remctrl", true
	case 2705:
		return "sds-admin", true
	case 2706:
		return "ncdmirroring", true
	case 2707:
		return "emcsymapiport", true
	case 2708:
		return "banyan-net", true
	case 2709:
		return "supermon", true
	case 2710:
		return "sso-service", true
	case 2711:
		return "sso-control", true
	case 2712:
		return "aocp", true
	case 2713:
		return "raventbs", true
	case 2714:
		return "raventdm", true
	case 2715:
		return "hpstgmgr2", true
	case 2716:
		return "inova-ip-disco", true
	case 2717:
		return "pn-requester", true
	case 2718:
		return "pn-requester2", true
	case 2719:
		return "scan-change", true
	case 2720:
		return "wkars", true
	case 2721:
		return "smart-diagnose", true
	case 2722:
		return "proactivesrvr", true
	case 2723:
		return "watchdog-nt", true
	case 2724:
		return "qotps", true
	case 2725:
		return "msolap-ptp2", true
	case 2726:
		return "tams", true
	case 2727:
		return "mgcp-callagent", true
	case 2728:
		return "sqdr", true
	case 2729:
		return "tcim-control", true
	case 2730:
		return "nec-raidplus", true
	case 2731:
		return "fyre-messanger", true
	case 2732:
		return "g5m", true
	case 2733:
		return "signet-ctf", true
	case 2734:
		return "ccs-software", true
	case 2735:
		return "netiq-mc", true
	case 2736:
		return "radwiz-nms-srv", true
	case 2737:
		return "srp-feedback", true
	case 2738:
		return "ndl-tcp-ois-gw", true
	case 2739:
		return "tn-timing", true
	case 2740:
		return "alarm", true
	case 2741:
		return "tsb", true
	case 2742:
		return "tsb2", true
	case 2743:
		return "murx", true
	case 2744:
		return "honyaku", true
	case 2745:
		return "urbisnet", true
	case 2746:
		return "cpudpencap", true
	case 2747:
		return "fjippol-swrly", true
	case 2748:
		return "fjippol-polsvr", true
	case 2749:
		return "fjippol-cnsl", true
	case 2750:
		return "fjippol-port1", true
	case 2751:
		return "fjippol-port2", true
	case 2752:
		return "rsisysaccess", true
	case 2753:
		return "de-spot", true
	case 2754:
		return "apollo-cc", true
	case 2755:
		return "expresspay", true
	case 2756:
		return "simplement-tie", true
	case 2757:
		return "cnrp", true
	case 2758:
		return "apollo-status", true
	case 2759:
		return "apollo-gms", true
	case 2760:
		return "sabams", true
	case 2761:
		return "dicom-iscl", true
	case 2762:
		return "dicom-tls", true
	case 2763:
		return "desktop-dna", true
	case 2764:
		return "data-insurance", true
	case 2765:
		return "qip-audup", true
	case 2766:
		return "compaq-scp", true
	case 2767:
		return "uadtc", true
	case 2768:
		return "uacs", true
	case 2769:
		return "exce", true
	case 2770:
		return "veronica", true
	case 2771:
		return "vergencecm", true
	case 2772:
		return "auris", true
	case 2773:
		return "rbakcup1", true
	case 2774:
		return "rbakcup2", true
	case 2775:
		return "smpp", true
	case 2776:
		return "ridgeway1", true
	case 2777:
		return "ridgeway2", true
	case 2778:
		return "gwen-sonya", true
	case 2779:
		return "lbc-sync", true
	case 2780:
		return "lbc-control", true
	case 2781:
		return "whosells", true
	case 2782:
		return "everydayrc", true
	case 2783:
		return "aises", true
	case 2784:
		return "www-dev", true
	case 2785:
		return "aic-np", true
	case 2786:
		return "aic-oncrpc", true
	case 2787:
		return "piccolo", true
	case 2788:
		return "fryeserv", true
	case 2789:
		return "media-agent", true
	case 2790:
		return "plgproxy", true
	case 2791:
		return "mtport-regist", true
	case 2792:
		return "f5-globalsite", true
	case 2793:
		return "initlsmsad", true
	case 2795:
		return "livestats", true
	case 2796:
		return "ac-tech", true
	case 2797:
		return "esp-encap", true
	case 2798:
		return "tmesis-upshot", true
	case 2799:
		return "icon-discover", true
	case 2800:
		return "acc-raid", true
	case 2801:
		return "igcp", true
	case 2802:
		return "veritas-udp1", true
	case 2803:
		return "btprjctrl", true
	case 2804:
		return "dvr-esm", true
	case 2805:
		return "wta-wsp-s", true
	case 2806:
		return "cspuni", true
	case 2807:
		return "cspmulti", true
	case 2808:
		return "j-lan-p", true
	case 2809:
		return "corbaloc", true
	case 2810:
		return "netsteward", true
	case 2811:
		return "gsiftp", true
	case 2812:
		return "atmtcp", true
	case 2813:
		return "llm-pass", true
	case 2814:
		return "llm-csv", true
	case 2815:
		return "lbc-measure", true
	case 2816:
		return "lbc-watchdog", true
	case 2817:
		return "nmsigport", true
	case 2818:
		return "rmlnk", true
	case 2819:
		return "fc-faultnotify", true
	case 2820:
		return "univision", true
	case 2821:
		return "vrts-at-port", true
	case 2822:
		return "ka0wuc", true
	case 2823:
		return "cqg-netlan", true
	case 2824:
		return "cqg-netlan-1", true
	case 2826:
		return "slc-systemlog", true
	case 2827:
		return "slc-ctrlrloops", true
	case 2828:
		return "itm-lm", true
	case 2829:
		return "silkp1", true
	case 2830:
		return "silkp2", true
	case 2831:
		return "silkp3", true
	case 2832:
		return "silkp4", true
	case 2833:
		return "glishd", true
	case 2834:
		return "evtp", true
	case 2835:
		return "evtp-data", true
	case 2836:
		return "catalyst", true
	case 2837:
		return "repliweb", true
	case 2838:
		return "starbot", true
	case 2839:
		return "nmsigport", true
	case 2840:
		return "l3-exprt", true
	case 2841:
		return "l3-ranger", true
	case 2842:
		return "l3-hawk", true
	case 2843:
		return "pdnet", true
	case 2844:
		return "bpcp-poll", true
	case 2845:
		return "bpcp-trap", true
	case 2846:
		return "aimpp-hello", true
	case 2847:
		return "aimpp-port-req", true
	case 2848:
		return "amt-blc-port", true
	case 2849:
		return "fxp", true
	case 2850:
		return "metaconsole", true
	case 2851:
		return "webemshttp", true
	case 2852:
		return "bears-01", true
	case 2853:
		return "ispipes", true
	case 2854:
		return "infomover", true
	case 2856:
		return "cesdinv", true
	case 2857:
		return "simctlp", true
	case 2858:
		return "ecnp", true
	case 2859:
		return "activememory", true
	case 2860:
		return "dialpad-voice1", true
	case 2861:
		return "dialpad-voice2", true
	case 2862:
		return "ttg-protocol", true
	case 2863:
		return "sonardata", true
	case 2864:
		return "astronova-main", true
	case 2865:
		return "pit-vpn", true
	case 2866:
		return "iwlistener", true
	case 2867:
		return "esps-portal", true
	case 2868:
		return "npep-messaging", true
	case 2869:
		return "icslap", true
	case 2870:
		return "daishi", true
	case 2871:
		return "msi-selectplay", true
	case 2872:
		return "radix", true
	case 2873:
		return "psrt", true
	case 2874:
		return "dxmessagebase1", true
	case 2875:
		return "dxmessagebase2", true
	case 2876:
		return "sps-tunnel", true
	case 2877:
		return "bluelance", true
	case 2878:
		return "aap", true
	case 2879:
		return "ucentric-ds", true
	case 2880:
		return "synapse", true
	case 2881:
		return "ndsp", true
	case 2882:
		return "ndtp", true
	case 2883:
		return "ndnp", true
	case 2884:
		return "flashmsg", true
	case 2885:
		return "topflow", true
	case 2886:
		return "responselogic", true
	case 2887:
		return "aironetddp", true
	case 2888:
		return "spcsdlobby", true
	case 2889:
		return "rsom", true
	case 2890:
		return "cspclmulti", true
	case 2891:
		return "cinegrfx-elmd", true
	case 2892:
		return "snifferdata", true
	case 2893:
		return "vseconnector", true
	case 2894:
		return "abacus-remote", true
	case 2895:
		return "natuslink", true
	case 2896:
		return "ecovisiong6-1", true
	case 2897:
		return "citrix-rtmp", true
	case 2898:
		return "appliance-cfg", true
	case 2899:
		return "powergemplus", true
	case 2900:
		return "quicksuite", true
	case 2901:
		return "allstorcns", true
	case 2902:
		return "netaspi", true
	case 2903:
		return "suitcase", true
	case 2904:
		return "m2ua", true
	case 2906:
		return "caller9", true
	case 2907:
		return "webmethods-b2b", true
	case 2908:
		return "mao", true
	case 2909:
		return "funk-dialout", true
	case 2910:
		return "tdaccess", true
	case 2911:
		return "blockade", true
	case 2912:
		return "epicon", true
	case 2913:
		return "boosterware", true
	case 2914:
		return "gamelobby", true
	case 2915:
		return "tksocket", true
	case 2916:
		return "elvin-server", true
	case 2917:
		return "elvin-client", true
	case 2918:
		return "kastenchasepad", true
	case 2919:
		return "roboer", true
	case 2920:
		return "roboeda", true
	case 2921:
		return "cesdcdman", true
	case 2922:
		return "cesdcdtrn", true
	case 2923:
		return "wta-wsp-wtp-s", true
	case 2924:
		return "precise-vip", true
	case 2926:
		return "mobile-file-dl", true
	case 2927:
		return "unimobilectrl", true
	case 2928:
		return "redstone-cpss", true
	case 2929:
		return "amx-webadmin", true
	case 2930:
		return "amx-weblinx", true
	case 2931:
		return "circle-x", true
	case 2932:
		return "incp", true
	case 2933:
		return "4-tieropmgw", true
	case 2934:
		return "4-tieropmcli", true
	case 2935:
		return "qtp", true
	case 2936:
		return "otpatch", true
	case 2937:
		return "pnaconsult-lm", true
	case 2938:
		return "sm-pas-1", true
	case 2939:
		return "sm-pas-2", true
	case 2940:
		return "sm-pas-3", true
	case 2941:
		return "sm-pas-4", true
	case 2942:
		return "sm-pas-5", true
	case 2943:
		return "ttnrepository", true
	case 2944:
		return "megaco-h248", true
	case 2945:
		return "h248-binary", true
	case 2946:
		return "fjsvmpor", true
	case 2947:
		return "gpsd", true
	case 2948:
		return "wap-push", true
	case 2949:
		return "wap-pushsecure", true
	case 2950:
		return "esip", true
	case 2951:
		return "ottp", true
	case 2952:
		return "mpfwsas", true
	case 2953:
		return "ovalarmsrv", true
	case 2954:
		return "ovalarmsrv-cmd", true
	case 2955:
		return "csnotify", true
	case 2956:
		return "ovrimosdbman", true
	case 2957:
		return "jmact5", true
	case 2958:
		return "jmact6", true
	case 2959:
		return "rmopagt", true
	case 2960:
		return "dfoxserver", true
	case 2961:
		return "boldsoft-lm", true
	case 2962:
		return "iph-policy-cli", true
	case 2963:
		return "iph-policy-adm", true
	case 2964:
		return "bullant-srap", true
	case 2965:
		return "bullant-rap", true
	case 2966:
		return "idp-infotrieve", true
	case 2967:
		return "ssc-agent", true
	case 2968:
		return "enpp", true
	case 2969:
		return "essp", true
	case 2970:
		return "index-net", true
	case 2971:
		return "netclip", true
	case 2972:
		return "pmsm-webrctl", true
	case 2973:
		return "svnetworks", true
	case 2974:
		return "signal", true
	case 2975:
		return "fjmpcm", true
	case 2976:
		return "cns-srv-port", true
	case 2977:
		return "ttc-etap-ns", true
	case 2978:
		return "ttc-etap-ds", true
	case 2979:
		return "h263-video", true
	case 2980:
		return "wimd", true
	case 2981:
		return "mylxamport", true
	case 2982:
		return "iwb-whiteboard", true
	case 2983:
		return "netplan", true
	case 2984:
		return "hpidsadmin", true
	case 2985:
		return "hpidsagent", true
	case 2986:
		return "stonefalls", true
	case 2987:
		return "identify", true
	case 2988:
		return "hippad", true
	case 2989:
		return "zarkov", true
	case 2990:
		return "boscap", true
	case 2991:
		return "wkstn-mon", true
	case 2992:
		return "avenyo", true
	case 2993:
		return "veritas-vis1", true
	case 2994:
		return "veritas-vis2", true
	case 2995:
		return "idrs", true
	case 2996:
		return "vsixml", true
	case 2997:
		return "rebol", true
	case 2998:
		return "realsecure", true
	case 2999:
		return "remoteware-un", true
	case 3000:
		return "hbci", true
	case 3002:
		return "exlm-agent", true
	case 3003:
		return "cgms", true
	case 3004:
		return "csoftragent", true
	case 3005:
		return "geniuslm", true
	case 3006:
		return "ii-admin", true
	case 3007:
		return "lotusmtap", true
	case 3008:
		return "midnight-tech", true
	case 3009:
		return "pxc-ntfy", true
	case 3010:
		return "ping-pong", true
	case 3011:
		return "trusted-web", true
	case 3012:
		return "twsdss", true
	case 3013:
		return "gilatskysurfer", true
	case 3014:
		return "broker-service", true
	case 3015:
		return "nati-dstp", true
	case 3016:
		return "notify-srvr", true
	case 3017:
		return "event-listener", true
	case 3018:
		return "srvc-registry", true
	case 3019:
		return "resource-mgr", true
	case 3020:
		return "cifs", true
	case 3021:
		return "agriserver", true
	case 3022:
		return "csregagent", true
	case 3023:
		return "magicnotes", true
	case 3024:
		return "nds-sso", true
	case 3025:
		return "arepa-raft", true
	case 3026:
		return "agri-gateway", true
	case 3027:
		return "LiebDevMgmt-C", true
	case 3028:
		return "LiebDevMgmt-DM", true
	case 3029:
		return "LiebDevMgmt-A", true
	case 3030:
		return "arepa-cas", true
	case 3031:
		return "eppc", true
	case 3032:
		return "redwood-chat", true
	case 3033:
		return "pdb", true
	case 3034:
		return "osmosis-aeea", true
	case 3035:
		return "fjsv-gssagt", true
	case 3036:
		return "hagel-dump", true
	case 3037:
		return "hp-san-mgmt", true
	case 3038:
		return "santak-ups", true
	case 3039:
		return "cogitate", true
	case 3040:
		return "tomato-springs", true
	case 3041:
		return "di-traceware", true
	case 3042:
		return "journee", true
	case 3043:
		return "brp", true
	case 3044:
		return "epp", true
	case 3045:
		return "responsenet", true
	case 3046:
		return "di-ase", true
	case 3047:
		return "hlserver", true
	case 3048:
		return "pctrader", true
	case 3049:
		return "nsws", true
	case 3050:
		return "gds-db", true
	case 3051:
		return "galaxy-server", true
	case 3052:
		return "apc-3052", true
	case 3053:
		return "dsom-server", true
	case 3054:
		return "amt-cnf-prot", true
	case 3055:
		return "policyserver", true
	case 3056:
		return "cdl-server", true
	case 3057:
		return "goahead-fldup", true
	case 3058:
		return "videobeans", true
	case 3059:
		return "qsoft", true
	case 3060:
		return "interserver", true
	case 3061:
		return "cautcpd", true
	case 3062:
		return "ncacn-ip-tcp", true
	case 3063:
		return "ncadg-ip-udp", true
	case 3064:
		return "rprt", true
	case 3065:
		return "slinterbase", true
	case 3066:
		return "netattachsdmp", true
	case 3067:
		return "fjhpjp", true
	case 3068:
		return "ls3bcast", true
	case 3069:
		return "ls3", true
	case 3070:
		return "mgxswitch", true
	case 3072:
		return "csd-monitor", true
	case 3073:
		return "vcrp", true
	case 3074:
		return "xbox", true
	case 3075:
		return "orbix-locator", true
	case 3076:
		return "orbix-config", true
	case 3077:
		return "orbix-loc-ssl", true
	case 3078:
		return "orbix-cfg-ssl", true
	case 3079:
		return "lv-frontpanel", true
	case 3080:
		return "stm-pproc", true
	case 3081:
		return "tl1-lv", true
	case 3082:
		return "tl1-raw", true
	case 3083:
		return "tl1-telnet", true
	case 3084:
		return "itm-mccs", true
	case 3085:
		return "pcihreq", true
	case 3086:
		return "jdl-dbkitchen", true
	case 3087:
		return "asoki-sma", true
	case 3088:
		return "xdtp", true
	case 3089:
		return "ptk-alink", true
	case 3090:
		return "stss", true
	case 3091:
		return "1ci-smcs", true
	case 3093:
		return "rapidmq-center", true
	case 3094:
		return "rapidmq-reg", true
	case 3095:
		return "panasas", true
	case 3096:
		return "ndl-aps", true
	case 3098:
		return "umm-port", true
	case 3099:
		return "chmd", true
	case 3100:
		return "opcon-xps", true
	case 3101:
		return "hp-pxpib", true
	case 3102:
		return "slslavemon", true
	case 3103:
		return "autocuesmi", true
	case 3104:
		return "autocuetime", true
	case 3105:
		return "cardbox", true
	case 3106:
		return "cardbox-http", true
	case 3107:
		return "business", true
	case 3108:
		return "geolocate", true
	case 3109:
		return "personnel", true
	case 3110:
		return "sim-control", true
	case 3111:
		return "wsynch", true
	case 3112:
		return "ksysguard", true
	case 3113:
		return "cs-auth-svr", true
	case 3114:
		return "ccmad", true
	case 3115:
		return "mctet-master", true
	case 3116:
		return "mctet-gateway", true
	case 3117:
		return "mctet-jserv", true
	case 3118:
		return "pkagent", true
	case 3119:
		return "d2000kernel", true
	case 3120:
		return "d2000webserver", true
	case 3122:
		return "vtr-emulator", true
	case 3123:
		return "edix", true
	case 3124:
		return "beacon-port", true
	case 3125:
		return "a13-an", true
	case 3127:
		return "ctx-bridge", true
	case 3128:
		return "ndl-aas", true
	case 3129:
		return "netport-id", true
	case 3130:
		return "icpv2", true
	case 3131:
		return "netbookmark", true
	case 3132:
		return "ms-rule-engine", true
	case 3133:
		return "prism-deploy", true
	case 3134:
		return "ecp", true
	case 3135:
		return "peerbook-port", true
	case 3136:
		return "grubd", true
	case 3137:
		return "rtnt-1", true
	case 3138:
		return "rtnt-2", true
	case 3139:
		return "incognitorv", true
	case 3140:
		return "ariliamulti", true
	case 3141:
		return "vmodem", true
	case 3142:
		return "rdc-wh-eos", true
	case 3143:
		return "seaview", true
	case 3144:
		return "tarantella", true
	case 3145:
		return "csi-lfap", true
	case 3146:
		return "bears-02", true
	case 3147:
		return "rfio", true
	case 3148:
		return "nm-game-admin", true
	case 3149:
		return "nm-game-server", true
	case 3150:
		return "nm-asses-admin", true
	case 3151:
		return "nm-assessor", true
	case 3152:
		return "feitianrockey", true
	case 3153:
		return "s8-client-port", true
	case 3154:
		return "ccmrmi", true
	case 3155:
		return "jpegmpeg", true
	case 3156:
		return "indura", true
	case 3157:
		return "e3consultants", true
	case 3158:
		return "stvp", true
	case 3159:
		return "navegaweb-port", true
	case 3160:
		return "tip-app-server", true
	case 3161:
		return "doc1lm", true
	case 3162:
		return "sflm", true
	case 3163:
		return "res-sap", true
	case 3164:
		return "imprs", true
	case 3165:
		return "newgenpay", true
	case 3166:
		return "sossecollector", true
	case 3167:
		return "nowcontact", true
	case 3168:
		return "poweronnud", true
	case 3169:
		return "serverview-as", true
	case 3170:
		return "serverview-asn", true
	case 3171:
		return "serverview-gf", true
	case 3172:
		return "serverview-rm", true
	case 3173:
		return "serverview-icc", true
	case 3174:
		return "armi-server", true
	case 3175:
		return "t1-e1-over-ip", true
	case 3176:
		return "ars-master", true
	case 3177:
		return "phonex-port", true
	case 3178:
		return "radclientport", true
	case 3179:
		return "h2gf-w-2m", true
	case 3180:
		return "mc-brk-srv", true
	case 3181:
		return "bmcpatrolagent", true
	case 3182:
		return "bmcpatrolrnvu", true
	case 3183:
		return "cops-tls", true
	case 3184:
		return "apogeex-port", true
	case 3185:
		return "smpppd", true
	case 3186:
		return "iiw-port", true
	case 3187:
		return "odi-port", true
	case 3188:
		return "brcm-comm-port", true
	case 3189:
		return "pcle-infex", true
	case 3190:
		return "csvr-proxy", true
	case 3191:
		return "csvr-sslproxy", true
	case 3192:
		return "firemonrcc", true
	case 3193:
		return "spandataport", true
	case 3194:
		return "magbind", true
	case 3195:
		return "ncu-1", true
	case 3196:
		return "ncu-2", true
	case 3197:
		return "embrace-dp-s", true
	case 3198:
		return "embrace-dp-c", true
	case 3199:
		return "dmod-workspace", true
	case 3200:
		return "tick-port", true
	case 3201:
		return "cpq-tasksmart", true
	case 3202:
		return "intraintra", true
	case 3203:
		return "netwatcher-mon", true
	case 3204:
		return "netwatcher-db", true
	case 3205:
		return "isns", true
	case 3206:
		return "ironmail", true
	case 3207:
		return "vx-auth-port", true
	case 3208:
		return "pfu-prcallback", true
	case 3209:
		return "netwkpathengine", true
	case 3210:
		return "flamenco-proxy", true
	case 3211:
		return "avsecuremgmt", true
	case 3212:
		return "surveyinst", true
	case 3213:
		return "neon24x7", true
	case 3214:
		return "jmq-daemon-1", true
	case 3215:
		return "jmq-daemon-2", true
	case 3216:
		return "ferrari-foam", true
	case 3217:
		return "unite", true
	case 3218:
		return "smartpackets", true
	case 3219:
		return "wms-messenger", true
	case 3220:
		return "xnm-ssl", true
	case 3221:
		return "xnm-clear-text", true
	case 3222:
		return "glbp", true
	case 3223:
		return "digivote", true
	case 3224:
		return "aes-discovery", true
	case 3225:
		return "fcip-port", true
	case 3226:
		return "isi-irp", true
	case 3227:
		return "dwnmshttp", true
	case 3228:
		return "dwmsgserver", true
	case 3229:
		return "global-cd-port", true
	case 3230:
		return "sftdst-port", true
	case 3231:
		return "vidigo", true
	case 3232:
		return "mdtp", true
	case 3233:
		return "whisker", true
	case 3234:
		return "alchemy", true
	case 3235:
		return "mdap-port", true
	case 3236:
		return "apparenet-ts", true
	case 3237:
		return "apparenet-tps", true
	case 3238:
		return "apparenet-as", true
	case 3239:
		return "apparenet-ui", true
	case 3240:
		return "triomotion", true
	case 3241:
		return "sysorb", true
	case 3242:
		return "sdp-id-port", true
	case 3243:
		return "timelot", true
	case 3244:
		return "onesaf", true
	case 3245:
		return "vieo-fe", true
	case 3246:
		return "dvt-system", true
	case 3247:
		return "dvt-data", true
	case 3248:
		return "procos-lm", true
	case 3249:
		return "ssp", true
	case 3250:
		return "hicp", true
	case 3251:
		return "sysscanner", true
	case 3252:
		return "dhe", true
	case 3253:
		return "pda-data", true
	case 3254:
		return "pda-sys", true
	case 3255:
		return "semaphore", true
	case 3256:
		return "cpqrpm-agent", true
	case 3257:
		return "cpqrpm-server", true
	case 3258:
		return "ivecon-port", true
	case 3259:
		return "epncdp2", true
	case 3260:
		return "iscsi-target", true
	case 3261:
		return "winshadow", true
	case 3262:
		return "necp", true
	case 3263:
		return "ecolor-imager", true
	case 3264:
		return "ccmail", true
	case 3265:
		return "altav-tunnel", true
	case 3266:
		return "ns-cfg-server", true
	case 3267:
		return "ibm-dial-out", true
	case 3268:
		return "msft-gc", true
	case 3269:
		return "msft-gc-ssl", true
	case 3270:
		return "verismart", true
	case 3271:
		return "csoft-prev", true
	case 3272:
		return "user-manager", true
	case 3273:
		return "sxmp", true
	case 3274:
		return "ordinox-server", true
	case 3275:
		return "samd", true
	case 3276:
		return "maxim-asics", true
	case 3277:
		return "awg-proxy", true
	case 3278:
		return "lkcmserver", true
	case 3279:
		return "admind", true
	case 3280:
		return "vs-server", true
	case 3281:
		return "sysopt", true
	case 3282:
		return "datusorb", true
	case 3283:
		return "Apple Remote Desktop (Net Assistant)", true
	case 3284:
		return "4talk", true
	case 3285:
		return "plato", true
	case 3286:
		return "e-net", true
	case 3287:
		return "directvdata", true
	case 3288:
		return "cops", true
	case 3289:
		return "enpc", true
	case 3290:
		return "caps-lm", true
	case 3291:
		return "sah-lm", true
	case 3292:
		return "cart-o-rama", true
	case 3293:
		return "fg-fps", true
	case 3294:
		return "fg-gip", true
	case 3295:
		return "dyniplookup", true
	case 3296:
		return "rib-slm", true
	case 3297:
		return "cytel-lm", true
	case 3298:
		return "deskview", true
	case 3299:
		return "pdrncs", true
	case 3301:
		return "tarantool", true
	case 3302:
		return "mcs-fastmail", true
	case 3303:
		return "opsession-clnt", true
	case 3304:
		return "opsession-srvr", true
	case 3305:
		return "odette-ftp", true
	case 3306:
		return "mysql", true
	case 3307:
		return "opsession-prxy", true
	case 3308:
		return "tns-server", true
	case 3309:
		return "tns-adv", true
	case 3310:
		return "dyna-access", true
	case 3311:
		return "mcns-tel-ret", true
	case 3312:
		return "appman-server", true
	case 3313:
		return "uorb", true
	case 3314:
		return "uohost", true
	case 3315:
		return "cdid", true
	case 3316:
		return "aicc-cmi", true
	case 3317:
		return "vsaiport", true
	case 3318:
		return "ssrip", true
	case 3319:
		return "sdt-lmd", true
	case 3320:
		return "officelink2000", true
	case 3321:
		return "vnsstr", true
	case 3326:
		return "sftu", true
	case 3327:
		return "bbars", true
	case 3328:
		return "egptlm", true
	case 3329:
		return "hp-device-disc", true
	case 3330:
		return "mcs-calypsoicf", true
	case 3331:
		return "mcs-messaging", true
	case 3332:
		return "mcs-mailsvr", true
	case 3333:
		return "dec-notes", true
	case 3334:
		return "directv-web", true
	case 3335:
		return "directv-soft", true
	case 3336:
		return "directv-tick", true
	case 3337:
		return "directv-catlg", true
	case 3338:
		return "anet-b", true
	case 3339:
		return "anet-l", true
	case 3340:
		return "anet-m", true
	case 3341:
		return "anet-h", true
	case 3342:
		return "webtie", true
	case 3343:
		return "ms-cluster-net", true
	case 3344:
		return "bnt-manager", true
	case 3345:
		return "influence", true
	case 3346:
		return "trnsprntproxy", true
	case 3347:
		return "phoenix-rpc", true
	case 3348:
		return "pangolin-laser", true
	case 3349:
		return "chevinservices", true
	case 3350:
		return "findviatv", true
	case 3351:
		return "btrieve", true
	case 3352:
		return "ssql", true
	case 3353:
		return "fatpipe", true
	case 3354:
		return "suitjd", true
	case 3355:
		return "ordinox-dbase", true
	case 3356:
		return "upnotifyps", true
	case 3357:
		return "adtech-test", true
	case 3358:
		return "mpsysrmsvr", true
	case 3359:
		return "wg-netforce", true
	case 3360:
		return "kv-server", true
	case 3361:
		return "kv-agent", true
	case 3362:
		return "dj-ilm", true
	case 3363:
		return "nati-vi-server", true
	case 3364:
		return "creativeserver", true
	case 3365:
		return "contentserver", true
	case 3366:
		return "creativepartnr", true
	case 3372:
		return "tip2", true
	case 3373:
		return "lavenir-lm", true
	case 3374:
		return "cluster-disc", true
	case 3375:
		return "vsnm-agent", true
	case 3376:
		return "cdbroker", true
	case 3377:
		return "cogsys-lm", true
	case 3378:
		return "wsicopy", true
	case 3379:
		return "socorfs", true
	case 3380:
		return "sns-channels", true
	case 3381:
		return "geneous", true
	case 3382:
		return "fujitsu-neat", true
	case 3383:
		return "esp-lm", true
	case 3384:
		return "hp-clic", true
	case 3385:
		return "qnxnetman", true
	case 3386:
		return "gprs-sig", true
	case 3387:
		return "backroomnet", true
	case 3388:
		return "cbserver", true
	case 3389:
		return "ms-wbt-server", true
	case 3390:
		return "dsc", true
	case 3391:
		return "savant", true
	case 3392:
		return "efi-lm", true
	case 3393:
		return "d2k-tapestry1", true
	case 3394:
		return "d2k-tapestry2", true
	case 3395:
		return "dyna-lm", true
	case 3396:
		return "printer-agent", true
	case 3397:
		return "cloanto-lm", true
	case 3398:
		return "mercantile", true
	case 3399:
		return "csms", true
	case 3400:
		return "csms2", true
	case 3401:
		return "filecast", true
	case 3402:
		return "fxaengine-net", true
	case 3405:
		return "nokia-ann-ch1", true
	case 3406:
		return "nokia-ann-ch2", true
	case 3407:
		return "ldap-admin", true
	case 3408:
		return "BESApi", true
	case 3409:
		return "networklens", true
	case 3410:
		return "networklenss", true
	case 3411:
		return "biolink-auth", true
	case 3412:
		return "xmlblaster", true
	case 3413:
		return "svnet", true
	case 3414:
		return "wip-port", true
	case 3415:
		return "bcinameservice", true
	case 3416:
		return "commandport", true
	case 3417:
		return "csvr", true
	case 3418:
		return "rnmap", true
	case 3419:
		return "softaudit", true
	case 3420:
		return "ifcp-port", true
	case 3421:
		return "bmap", true
	case 3422:
		return "rusb-sys-port", true
	case 3423:
		return "xtrm", true
	case 3424:
		return "xtrms", true
	case 3425:
		return "agps-port", true
	case 3426:
		return "arkivio", true
	case 3427:
		return "websphere-snmp", true
	case 3428:
		return "twcss", true
	case 3429:
		return "gcsp", true
	case 3430:
		return "ssdispatch", true
	case 3431:
		return "ndl-als", true
	case 3432:
		return "osdcp", true
	case 3433:
		return "opnet-smp", true
	case 3434:
		return "opencm", true
	case 3435:
		return "pacom", true
	case 3436:
		return "gc-config", true
	case 3437:
		return "autocueds", true
	case 3438:
		return "spiral-admin", true
	case 3439:
		return "hri-port", true
	case 3440:
		return "ans-console", true
	case 3441:
		return "connect-client", true
	case 3442:
		return "connect-server", true
	case 3443:
		return "ov-nnm-websrv", true
	case 3444:
		return "denali-server", true
	case 3445:
		return "monp", true
	case 3446:
		return "3comfaxrpc", true
	case 3447:
		return "directnet", true
	case 3448:
		return "dnc-port", true
	case 3449:
		return "hotu-chat", true
	case 3450:
		return "castorproxy", true
	case 3451:
		return "asam", true
	case 3452:
		return "sabp-signal", true
	case 3453:
		return "pscupd", true
	case 3454:
		return "mira", true
	case 3455:
		return "prsvp", true
	case 3456:
		return "vat", true
	case 3457:
		return "vat-control", true
	case 3458:
		return "d3winosfi", true
	case 3459:
		return "integral", true
	case 3460:
		return "edm-manager", true
	case 3461:
		return "edm-stager", true
	case 3462:
		return "edm-std-notify", true
	case 3463:
		return "edm-adm-notify", true
	case 3464:
		return "edm-mgr-sync", true
	case 3465:
		return "edm-mgr-cntrl", true
	case 3466:
		return "workflow", true
	case 3467:
		return "rcst", true
	case 3468:
		return "ttcmremotectrl", true
	case 3469:
		return "pluribus", true
	case 3470:
		return "jt400", true
	case 3471:
		return "jt400-ssl", true
	case 3472:
		return "jaugsremotec-1", true
	case 3473:
		return "jaugsremotec-2", true
	case 3474:
		return "ttntspauto", true
	case 3475:
		return "genisar-port", true
	case 3476:
		return "nppmp", true
	case 3477:
		return "ecomm", true
	case 3478:
		return "stun", true
	case 3479:
		return "twrpc", true
	case 3480:
		return "plethora", true
	case 3481:
		return "cleanerliverc", true
	case 3482:
		return "vulture", true
	case 3483:
		return "slim-devices", true
	case 3484:
		return "gbs-stp", true
	case 3485:
		return "celatalk", true
	case 3486:
		return "ifsf-hb-port", true
	case 3487:
		return "ltcudp", true
	case 3488:
		return "fs-rh-srv", true
	case 3489:
		return "dtp-dia", true
	case 3490:
		return "colubris", true
	case 3491:
		return "swr-port", true
	case 3492:
		return "tvdumtray-port", true
	case 3493:
		return "nut", true
	case 3494:
		return "ibm3494", true
	case 3495:
		return "seclayer-tcp", true
	case 3496:
		return "seclayer-tls", true
	case 3497:
		return "ipether232port", true
	case 3498:
		return "dashpas-port", true
	case 3499:
		return "sccip-media", true
	case 3500:
		return "rtmp-port", true
	case 3501:
		return "isoft-p2p", true
	case 3502:
		return "avinstalldisc", true
	case 3503:
		return "lsp-ping", true
	case 3504:
		return "ironstorm", true
	case 3505:
		return "ccmcomm", true
	case 3506:
		return "apc-3506", true
	case 3507:
		return "nesh-broker", true
	case 3508:
		return "interactionweb", true
	case 3509:
		return "vt-ssl", true
	case 3510:
		return "xss-port", true
	case 3511:
		return "webmail-2", true
	case 3512:
		return "aztec", true
	case 3513:
		return "arcpd", true
	case 3514:
		return "must-p2p", true
	case 3515:
		return "must-backplane", true
	case 3516:
		return "smartcard-port", true
	case 3517:
		return "802-11-iapp", true
	case 3518:
		return "artifact-msg", true
	case 3519:
		return "galileo", true
	case 3520:
		return "galileolog", true
	case 3521:
		return "mc3ss", true
	case 3522:
		return "nssocketport", true
	case 3523:
		return "odeumservlink", true
	case 3524:
		return "ecmport", true
	case 3525:
		return "eisport", true
	case 3526:
		return "starquiz-port", true
	case 3527:
		return "beserver-msg-q", true
	case 3528:
		return "jboss-iiop", true
	case 3529:
		return "jboss-iiop-ssl", true
	case 3530:
		return "gf", true
	case 3531:
		return "joltid", true
	case 3532:
		return "raven-rmp", true
	case 3533:
		return "raven-rdp", true
	case 3534:
		return "urld-port", true
	case 3535:
		return "ms-la", true
	case 3536:
		return "snac", true
	case 3537:
		return "ni-visa-remote", true
	case 3538:
		return "ibm-diradm", true
	case 3539:
		return "ibm-diradm-ssl", true
	case 3540:
		return "pnrp-port", true
	case 3541:
		return "voispeed-port", true
	case 3542:
		return "hacl-monitor", true
	case 3543:
		return "qftest-lookup", true
	case 3544:
		return "teredo", true
	case 3545:
		return "camac", true
	case 3547:
		return "symantec-sim", true
	case 3548:
		return "interworld", true
	case 3549:
		return "tellumat-nms", true
	case 3550:
		return "ssmpp", true
	case 3551:
		return "apcupsd", true
	case 3552:
		return "taserver", true
	case 3553:
		return "rbr-discovery", true
	case 3554:
		return "questnotify", true
	case 3555:
		return "razor", true
	case 3556:
		return "sky-transport", true
	case 3557:
		return "personalos-001", true
	case 3558:
		return "mcp-port", true
	case 3559:
		return "cctv-port", true
	case 3560:
		return "iniserve-port", true
	case 3561:
		return "bmc-onekey", true
	case 3562:
		return "sdbproxy", true
	case 3563:
		return "watcomdebug", true
	case 3564:
		return "esimport", true
	case 3567:
		return "dof-eps", true
	case 3568:
		return "dof-tunnel-sec", true
	case 3569:
		return "mbg-ctrl", true
	case 3570:
		return "mccwebsvr-port", true
	case 3571:
		return "megardsvr-port", true
	case 3572:
		return "megaregsvrport", true
	case 3573:
		return "tag-ups-1", true
	case 3574:
		return "dmaf-caster", true
	case 3575:
		return "ccm-port", true
	case 3576:
		return "cmc-port", true
	case 3577:
		return "config-port", true
	case 3578:
		return "data-port", true
	case 3579:
		return "ttat3lb", true
	case 3580:
		return "nati-svrloc", true
	case 3581:
		return "kfxaclicensing", true
	case 3582:
		return "press", true
	case 3583:
		return "canex-watch", true
	case 3584:
		return "u-dbap", true
	case 3585:
		return "emprise-lls", true
	case 3586:
		return "emprise-lsc", true
	case 3587:
		return "p2pgroup", true
	case 3588:
		return "sentinel", true
	case 3589:
		return "isomair", true
	case 3590:
		return "wv-csp-sms", true
	case 3591:
		return "gtrack-server", true
	case 3592:
		return "gtrack-ne", true
	case 3593:
		return "bpmd", true
	case 3594:
		return "mediaspace", true
	case 3595:
		return "shareapp", true
	case 3596:
		return "iw-mmogame", true
	case 3597:
		return "a14", true
	case 3598:
		return "a15", true
	case 3599:
		return "quasar-server", true
	case 3600:
		return "trap-daemon", true
	case 3601:
		return "visinet-gui", true
	case 3602:
		return "infiniswitchcl", true
	case 3603:
		return "int-rcv-cntrl", true
	case 3604:
		return "bmc-jmx-port", true
	case 3605:
		return "comcam-io", true
	case 3606:
		return "splitlock", true
	case 3607:
		return "precise-i3", true
	case 3608:
		return "trendchip-dcp", true
	case 3609:
		return "cpdi-pidas-cm", true
	case 3610:
		return "echonet", true
	case 3611:
		return "six-degrees", true
	case 3612:
		return "dataprotector", true
	case 3613:
		return "alaris-disc", true
	case 3614:
		return "sigma-port", true
	case 3615:
		return "start-network", true
	case 3616:
		return "cd3o-protocol", true
	case 3617:
		return "sharp-server", true
	case 3618:
		return "aairnet-1", true
	case 3619:
		return "aairnet-2", true
	case 3620:
		return "ep-pcp", true
	case 3621:
		return "ep-nsp", true
	case 3622:
		return "ff-lr-port", true
	case 3623:
		return "haipe-discover", true
	case 3624:
		return "dist-upgrade", true
	case 3625:
		return "volley", true
	case 3626:
		return "bvcdaemon-port", true
	case 3627:
		return "jamserverport", true
	case 3628:
		return "ept-machine", true
	case 3629:
		return "escvpnet", true
	case 3630:
		return "cs-remote-db", true
	case 3631:
		return "cs-services", true
	case 3632:
		return "distcc", true
	case 3633:
		return "wacp", true
	case 3634:
		return "hlibmgr", true
	case 3635:
		return "sdo", true
	case 3636:
		return "servistaitsm", true
	case 3637:
		return "scservp", true
	case 3638:
		return "ehp-backup", true
	case 3639:
		return "xap-ha", true
	case 3640:
		return "netplay-port1", true
	case 3641:
		return "netplay-port2", true
	case 3642:
		return "juxml-port", true
	case 3643:
		return "audiojuggler", true
	case 3644:
		return "ssowatch", true
	case 3645:
		return "cyc", true
	case 3646:
		return "xss-srv-port", true
	case 3647:
		return "splitlock-gw", true
	case 3648:
		return "fjcp", true
	case 3649:
		return "nmmp", true
	case 3650:
		return "prismiq-plugin", true
	case 3651:
		return "xrpc-registry", true
	case 3652:
		return "vxcrnbuport", true
	case 3653:
		return "tsp", true
	case 3654:
		return "vaprtm", true
	case 3655:
		return "abatemgr", true
	case 3656:
		return "abatjss", true
	case 3657:
		return "immedianet-bcn", true
	case 3658:
		return "ps-ams", true
	case 3659:
		return "apple-sasl", true
	case 3660:
		return "can-nds-ssl", true
	case 3661:
		return "can-ferret-ssl", true
	case 3662:
		return "pserver", true
	case 3663:
		return "dtp", true
	case 3664:
		return "ups-engine", true
	case 3665:
		return "ent-engine", true
	case 3666:
		return "eserver-pap", true
	case 3667:
		return "infoexch", true
	case 3668:
		return "dell-rm-port", true
	case 3669:
		return "casanswmgmt", true
	case 3670:
		return "smile", true
	case 3671:
		return "efcp", true
	case 3672:
		return "lispworks-orb", true
	case 3673:
		return "mediavault-gui", true
	case 3674:
		return "wininstall-ipc", true
	case 3675:
		return "calltrax", true
	case 3676:
		return "va-pacbase", true
	case 3677:
		return "roverlog", true
	case 3678:
		return "ipr-dglt", true
	case 3679:
		return "Escale (Newton Dock)", true
	case 3680:
		return "npds-tracker", true
	case 3681:
		return "bts-x73", true
	case 3682:
		return "cas-mapi", true
	case 3683:
		return "bmc-ea", true
	case 3684:
		return "faxstfx-port", true
	case 3685:
		return "dsx-agent", true
	case 3686:
		return "tnmpv2", true
	case 3687:
		return "simple-push", true
	case 3688:
		return "simple-push-s", true
	case 3689:
		return "daap", true
	case 3690:
		return "svn", true
	case 3691:
		return "magaya-network", true
	case 3692:
		return "intelsync", true
	case 3695:
		return "bmc-data-coll", true
	case 3696:
		return "telnetcpcd", true
	case 3697:
		return "nw-license", true
	case 3698:
		return "sagectlpanel", true
	case 3699:
		return "kpn-icw", true
	case 3700:
		return "lrs-paging", true
	case 3701:
		return "netcelera", true
	case 3702:
		return "ws-discovery", true
	case 3703:
		return "adobeserver-3", true
	case 3704:
		return "adobeserver-4", true
	case 3705:
		return "adobeserver-5", true
	case 3706:
		return "rt-event", true
	case 3707:
		return "rt-event-s", true
	case 3708:
		return "sun-as-iiops", true
	case 3709:
		return "ca-idms", true
	case 3710:
		return "portgate-auth", true
	case 3711:
		return "edb-server2", true
	case 3712:
		return "sentinel-ent", true
	case 3713:
		return "tftps", true
	case 3714:
		return "delos-dms", true
	case 3715:
		return "anoto-rendezv", true
	case 3716:
		return "wv-csp-sms-cir", true
	case 3717:
		return "wv-csp-udp-cir", true
	case 3718:
		return "opus-services", true
	case 3719:
		return "itelserverport", true
	case 3720:
		return "ufastro-instr", true
	case 3721:
		return "xsync", true
	case 3722:
		return "xserveraid", true
	case 3723:
		return "sychrond", true
	case 3724:
		return "blizwow", true
	case 3725:
		return "na-er-tip", true
	case 3726:
		return "array-manager", true
	case 3727:
		return "e-mdu", true
	case 3728:
		return "e-woa", true
	case 3729:
		return "fksp-audit", true
	case 3730:
		return "client-ctrl", true
	case 3731:
		return "smap", true
	case 3732:
		return "m-wnn", true
	case 3733:
		return "multip-msg", true
	case 3734:
		return "synel-data", true
	case 3735:
		return "pwdis", true
	case 3736:
		return "rs-rmi", true
	case 3738:
		return "versatalk", true
	case 3739:
		return "launchbird-lm", true
	case 3740:
		return "heartbeat", true
	case 3741:
		return "wysdma", true
	case 3742:
		return "cst-port", true
	case 3743:
		return "ipcs-command", true
	case 3744:
		return "sasg", true
	case 3745:
		return "gw-call-port", true
	case 3746:
		return "linktest", true
	case 3747:
		return "linktest-s", true
	case 3748:
		return "webdata", true
	case 3749:
		return "cimtrak", true
	case 3750:
		return "cbos-ip-port", true
	case 3751:
		return "gprs-cube", true
	case 3752:
		return "vipremoteagent", true
	case 3753:
		return "nattyserver", true
	case 3754:
		return "timestenbroker", true
	case 3755:
		return "sas-remote-hlp", true
	case 3756:
		return "canon-capt", true
	case 3757:
		return "grf-port", true
	case 3758:
		return "apw-registry", true
	case 3759:
		return "exapt-lmgr", true
	case 3760:
		return "adtempusclient", true
	case 3761:
		return "gsakmp", true
	case 3762:
		return "gbs-smp", true
	case 3763:
		return "xo-wave", true
	case 3764:
		return "mni-prot-rout", true
	case 3765:
		return "rtraceroute", true
	case 3767:
		return "listmgr-port", true
	case 3768:
		return "rblcheckd", true
	case 3769:
		return "haipe-otnk", true
	case 3770:
		return "cindycollab", true
	case 3771:
		return "paging-port", true
	case 3772:
		return "ctp", true
	case 3773:
		return "ctdhercules", true
	case 3774:
		return "zicom", true
	case 3775:
		return "ispmmgr", true
	case 3776:
		return "dvcprov-port", true
	case 3777:
		return "jibe-eb", true
	case 3778:
		return "c-h-it-port", true
	case 3779:
		return "cognima", true
	case 3780:
		return "nnp", true
	case 3781:
		return "abcvoice-port", true
	case 3782:
		return "iso-tp0s", true
	case 3783:
		return "bim-pem", true
	case 3784:
		return "bfd-control", true
	case 3785:
		return "bfd-echo", true
	case 3786:
		return "upstriggervsw", true
	case 3787:
		return "fintrx", true
	case 3788:
		return "isrp-port", true
	case 3789:
		return "remotedeploy", true
	case 3790:
		return "quickbooksrds", true
	case 3791:
		return "tvnetworkvideo", true
	case 3792:
		return "sitewatch", true
	case 3793:
		return "dcsoftware", true
	case 3794:
		return "jaus", true
	case 3795:
		return "myblast", true
	case 3796:
		return "spw-dialer", true
	case 3797:
		return "idps", true
	case 3798:
		return "minilock", true
	case 3799:
		return "radius-dynauth", true
	case 3800:
		return "pwgpsi", true
	case 3801:
		return "ibm-mgr", true
	case 3802:
		return "vhd", true
	case 3803:
		return "soniqsync", true
	case 3804:
		return "iqnet-port", true
	case 3805:
		return "tcpdataserver", true
	case 3806:
		return "wsmlb", true
	case 3807:
		return "spugna", true
	case 3808:
		return "sun-as-iiops-ca", true
	case 3809:
		return "apocd", true
	case 3810:
		return "wlanauth", true
	case 3811:
		return "amp", true
	case 3812:
		return "neto-wol-server", true
	case 3813:
		return "rap-ip", true
	case 3814:
		return "neto-dcs", true
	case 3815:
		return "lansurveyorxml", true
	case 3816:
		return "sunlps-http", true
	case 3817:
		return "tapeware", true
	case 3818:
		return "crinis-hb", true
	case 3819:
		return "epl-slp", true
	case 3820:
		return "scp", true
	case 3821:
		return "pmcp", true
	case 3822:
		return "acp-discovery", true
	case 3823:
		return "acp-conduit", true
	case 3824:
		return "acp-policy", true
	case 3825:
		return "ffserver", true
	case 3826:
		return "warmux", true
	case 3827:
		return "netmpi", true
	case 3828:
		return "neteh", true
	case 3829:
		return "neteh-ext", true
	case 3830:
		return "cernsysmgmtagt", true
	case 3831:
		return "dvapps", true
	case 3832:
		return "xxnetserver", true
	case 3833:
		return "aipn-auth", true
	case 3834:
		return "spectardata", true
	case 3835:
		return "spectardb", true
	case 3836:
		return "markem-dcp", true
	case 3837:
		return "mkm-discovery", true
	case 3838:
		return "sos", true
	case 3839:
		return "amx-rms", true
	case 3840:
		return "flirtmitmir", true
	case 3842:
		return "nhci", true
	case 3843:
		return "quest-agent", true
	case 3844:
		return "rnm", true
	case 3845:
		return "v-one-spp", true
	case 3846:
		return "an-pcp", true
	case 3847:
		return "msfw-control", true
	case 3848:
		return "item", true
	case 3849:
		return "spw-dnspreload", true
	case 3850:
		return "qtms-bootstrap", true
	case 3851:
		return "spectraport", true
	case 3852:
		return "sse-app-config", true
	case 3853:
		return "sscan", true
	case 3854:
		return "stryker-com", true
	case 3855:
		return "opentrac", true
	case 3856:
		return "informer", true
	case 3857:
		return "trap-port", true
	case 3858:
		return "trap-port-mom", true
	case 3859:
		return "nav-port", true
	case 3860:
		return "sasp", true
	case 3861:
		return "winshadow-hd", true
	case 3862:
		return "giga-pocket", true
	case 3863:
		return "asap-udp", true
	case 3865:
		return "xpl", true
	case 3866:
		return "dzdaemon", true
	case 3867:
		return "dzoglserver", true
	case 3869:
		return "ovsam-mgmt", true
	case 3870:
		return "ovsam-d-agent", true
	case 3871:
		return "avocent-adsap", true
	case 3872:
		return "oem-agent", true
	case 3873:
		return "fagordnc", true
	case 3874:
		return "sixxsconfig", true
	case 3875:
		return "pnbscada", true
	case 3876:
		return "dl-agent", true
	case 3877:
		return "xmpcr-interface", true
	case 3878:
		return "fotogcad", true
	case 3879:
		return "appss-lm", true
	case 3880:
		return "igrs", true
	case 3881:
		return "idac", true
	case 3882:
		return "msdts1", true
	case 3883:
		return "vrpn", true
	case 3884:
		return "softrack-meter", true
	case 3885:
		return "topflow-ssl", true
	case 3886:
		return "nei-management", true
	case 3887:
		return "ciphire-data", true
	case 3888:
		return "ciphire-serv", true
	case 3889:
		return "dandv-tester", true
	case 3890:
		return "ndsconnect", true
	case 3891:
		return "rtc-pm-port", true
	case 3892:
		return "pcc-image-port", true
	case 3893:
		return "cgi-starapi", true
	case 3894:
		return "syam-agent", true
	case 3895:
		return "syam-smc", true
	case 3896:
		return "sdo-tls", true
	case 3897:
		return "sdo-ssh", true
	case 3898:
		return "senip", true
	case 3899:
		return "itv-control", true
	case 3900:
		return "udt-os", true
	case 3901:
		return "nimsh", true
	case 3902:
		return "nimaux", true
	case 3903:
		return "charsetmgr", true
	case 3904:
		return "omnilink-port", true
	case 3905:
		return "mupdate", true
	case 3906:
		return "topovista-data", true
	case 3907:
		return "imoguia-port", true
	case 3908:
		return "hppronetman", true
	case 3909:
		return "surfcontrolcpa", true
	case 3910:
		return "prnrequest", true
	case 3911:
		return "prnstatus", true
	case 3912:
		return "gbmt-stars", true
	case 3913:
		return "listcrt-port", true
	case 3914:
		return "listcrt-port-2", true
	case 3915:
		return "agcat", true
	case 3916:
		return "wysdmc", true
	case 3917:
		return "aftmux", true
	case 3918:
		return "pktcablemmcops", true
	case 3919:
		return "hyperip", true
	case 3920:
		return "exasoftport1", true
	case 3921:
		return "herodotus-net", true
	case 3922:
		return "sor-update", true
	case 3923:
		return "symb-sb-port", true
	case 3924:
		return "mpl-gprs-port", true
	case 3925:
		return "zmp", true
	case 3926:
		return "winport", true
	case 3927:
		return "natdataservice", true
	case 3928:
		return "netboot-pxe", true
	case 3929:
		return "smauth-port", true
	case 3930:
		return "syam-webserver", true
	case 3931:
		return "msr-plugin-port", true
	case 3932:
		return "dyn-site", true
	case 3933:
		return "plbserve-port", true
	case 3934:
		return "sunfm-port", true
	case 3935:
		return "sdp-portmapper", true
	case 3936:
		return "mailprox", true
	case 3937:
		return "dvbservdsc", true
	case 3938:
		return "dbcontrol-agent", true
	case 3939:
		return "aamp", true
	case 3940:
		return "xecp-node", true
	case 3941:
		return "homeportal-web", true
	case 3942:
		return "srdp", true
	case 3943:
		return "tig", true
	case 3944:
		return "sops", true
	case 3945:
		return "emcads", true
	case 3946:
		return "backupedge", true
	case 3947:
		return "ccp", true
	case 3948:
		return "apdap", true
	case 3949:
		return "drip", true
	case 3950:
		return "namemunge", true
	case 3951:
		return "pwgippfax", true
	case 3952:
		return "i3-sessionmgr", true
	case 3953:
		return "xmlink-connect", true
	case 3954:
		return "adrep", true
	case 3955:
		return "p2pcommunity", true
	case 3956:
		return "gvcp", true
	case 3957:
		return "mqe-broker", true
	case 3958:
		return "mqe-agent", true
	case 3959:
		return "treehopper", true
	case 3960:
		return "bess", true
	case 3961:
		return "proaxess", true
	case 3962:
		return "sbi-agent", true
	case 3963:
		return "thrp", true
	case 3964:
		return "sasggprs", true
	case 3965:
		return "ati-ip-to-ncpe", true
	case 3966:
		return "bflckmgr", true
	case 3967:
		return "ppsms", true
	case 3968:
		return "ianywhere-dbns", true
	case 3969:
		return "landmarks", true
	case 3970:
		return "lanrevagent", true
	case 3971:
		return "lanrevserver", true
	case 3972:
		return "iconp", true
	case 3973:
		return "progistics", true
	case 3974:
		return "xk22", true
	case 3975:
		return "airshot", true
	case 3976:
		return "opswagent", true
	case 3977:
		return "opswmanager", true
	case 3978:
		return "secure-cfg-svr", true
	case 3979:
		return "smwan", true
	case 3981:
		return "starfish", true
	case 3982:
		return "eis", true
	case 3983:
		return "eisp", true
	case 3984:
		return "mapper-nodemgr", true
	case 3985:
		return "mapper-mapethd", true
	case 3986:
		return "mapper-ws-ethd", true
	case 3987:
		return "centerline", true
	case 3988:
		return "dcs-config", true
	case 3989:
		return "bv-queryengine", true
	case 3990:
		return "bv-is", true
	case 3991:
		return "bv-smcsrv", true
	case 3992:
		return "bv-ds", true
	case 3993:
		return "bv-agent", true
	case 3995:
		return "iss-mgmt-ssl", true
	case 3996:
		return "abcsoftware", true
	case 3997:
		return "agentsease-db", true
	case 3998:
		return "dnx", true
	case 3999:
		return "nvcnet", true
	case 4000:
		return "terabase", true
	case 4001:
		return "newoak", true
	case 4002:
		return "pxc-spvr-ft", true
	case 4003:
		return "pxc-splr-ft", true
	case 4004:
		return "pxc-roid", true
	case 4005:
		return "pxc-pin", true
	case 4006:
		return "pxc-spvr", true
	case 4007:
		return "pxc-splr", true
	case 4008:
		return "netcheque", true
	case 4009:
		return "chimera-hwm", true
	case 4010:
		return "samsung-unidex", true
	case 4011:
		return "altserviceboot", true
	case 4012:
		return "pda-gate", true
	case 4013:
		return "acl-manager", true
	case 4014:
		return "taiclock", true
	case 4015:
		return "talarian-mcast1", true
	case 4016:
		return "talarian-mcast2", true
	case 4017:
		return "talarian-mcast3", true
	case 4018:
		return "talarian-mcast4", true
	case 4019:
		return "talarian-mcast5", true
	case 4020:
		return "trap", true
	case 4021:
		return "nexus-portal", true
	case 4022:
		return "dnox", true
	case 4023:
		return "esnm-zoning", true
	case 4024:
		return "tnp1-port", true
	case 4025:
		return "partimage", true
	case 4026:
		return "as-debug", true
	case 4027:
		return "bxp", true
	case 4028:
		return "dtserver-port", true
	case 4029:
		return "ip-qsig", true
	case 4030:
		return "jdmn-port", true
	case 4031:
		return "suucp", true
	case 4032:
		return "vrts-auth-port", true
	case 4033:
		return "sanavigator", true
	case 4034:
		return "ubxd", true
	case 4035:
		return "wap-push-http", true
	case 4036:
		return "wap-push-https", true
	case 4037:
		return "ravehd", true
	case 4038:
		return "fazzt-ptp", true
	case 4039:
		return "fazzt-admin", true
	case 4040:
		return "yo-main", true
	case 4041:
		return "houston", true
	case 4042:
		return "ldxp", true
	case 4043:
		return "nirp", true
	case 4044:
		return "ltp", true
	case 4045:
		return "npp", true
	case 4046:
		return "acp-proto", true
	case 4047:
		return "ctp-state", true
	case 4049:
		return "wafs", true
	case 4050:
		return "cisco-wafs", true
	case 4051:
		return "cppdp", true
	case 4052:
		return "interact", true
	case 4053:
		return "ccu-comm-1", true
	case 4054:
		return "ccu-comm-2", true
	case 4055:
		return "ccu-comm-3", true
	case 4056:
		return "lms", true
	case 4057:
		return "wfm", true
	case 4058:
		return "kingfisher", true
	case 4059:
		return "dlms-cosem", true
	case 4060:
		return "dsmeter-iatc", true
	case 4061:
		return "ice-location", true
	case 4062:
		return "ice-slocation", true
	case 4063:
		return "ice-router", true
	case 4064:
		return "ice-srouter", true
	case 4065:
		return "avanti-cdp", true
	case 4066:
		return "pmas", true
	case 4067:
		return "idp", true
	case 4068:
		return "ipfltbcst", true
	case 4069:
		return "minger", true
	case 4070:
		return "tripe", true
	case 4071:
		return "aibkup", true
	case 4072:
		return "zieto-sock", true
	case 4073:
		return "iRAPP", true
	case 4074:
		return "cequint-cityid", true
	case 4075:
		return "perimlan", true
	case 4076:
		return "seraph", true
	case 4077:
		return "ascomalarm", true
	case 4079:
		return "santools", true
	case 4080:
		return "lorica-in", true
	case 4081:
		return "lorica-in-sec", true
	case 4082:
		return "lorica-out", true
	case 4083:
		return "lorica-out-sec", true
	case 4084:
		return "fortisphere-vm", true
	case 4086:
		return "ftsync", true
	case 4089:
		return "opencore", true
	case 4090:
		return "omasgport", true
	case 4091:
		return "ewinstaller", true
	case 4092:
		return "ewdgs", true
	case 4093:
		return "pvxpluscs", true
	case 4094:
		return "sysrqd", true
	case 4095:
		return "xtgui", true
	case 4096:
		return "bre", true
	case 4097:
		return "patrolview", true
	case 4098:
		return "drmsfsd", true
	case 4099:
		return "dpcp", true
	case 4100:
		return "igo-incognito", true
	case 4101:
		return "brlp-0", true
	case 4102:
		return "brlp-1", true
	case 4103:
		return "brlp-2", true
	case 4104:
		return "brlp-3", true
	case 4105:
		return "shofar", true
	case 4106:
		return "synchronite", true
	case 4107:
		return "j-ac", true
	case 4108:
		return "accel", true
	case 4109:
		return "izm", true
	case 4110:
		return "g2tag", true
	case 4111:
		return "xgrid", true
	case 4112:
		return "apple-vpns-rp", true
	case 4113:
		return "aipn-reg", true
	case 4114:
		return "jomamqmonitor", true
	case 4115:
		return "cds", true
	case 4116:
		return "smartcard-tls", true
	case 4117:
		return "hillrserv", true
	case 4118:
		return "netscript", true
	case 4119:
		return "assuria-slm", true
	case 4121:
		return "e-builder", true
	case 4122:
		return "fprams", true
	case 4123:
		return "z-wave", true
	case 4124:
		return "tigv2", true
	case 4125:
		return "opsview-envoy", true
	case 4126:
		return "ddrepl", true
	case 4127:
		return "unikeypro", true
	case 4128:
		return "nufw", true
	case 4129:
		return "nuauth", true
	case 4130:
		return "fronet", true
	case 4131:
		return "stars", true
	case 4132:
		return "nuts-dem", true
	case 4133:
		return "nuts-bootp", true
	case 4134:
		return "nifty-hmi", true
	case 4135:
		return "cl-db-attach", true
	case 4136:
		return "cl-db-request", true
	case 4137:
		return "cl-db-remote", true
	case 4138:
		return "nettest", true
	case 4139:
		return "thrtx", true
	case 4140:
		return "cedros-fds", true
	case 4141:
		return "oirtgsvc", true
	case 4142:
		return "oidocsvc", true
	case 4143:
		return "oidsr", true
	case 4145:
		return "vvr-control", true
	case 4146:
		return "tgcconnect", true
	case 4147:
		return "vrxpservman", true
	case 4148:
		return "hhb-handheld", true
	case 4149:
		return "agslb", true
	case 4150:
		return "PowerAlert-nsa", true
	case 4151:
		return "menandmice-noh", true
	case 4152:
		return "idig-mux", true
	case 4153:
		return "mbl-battd", true
	case 4154:
		return "atlinks", true
	case 4155:
		return "bzr", true
	case 4156:
		return "stat-results", true
	case 4157:
		return "stat-scanner", true
	case 4158:
		return "stat-cc", true
	case 4159:
		return "nss", true
	case 4160:
		return "jini-discovery", true
	case 4161:
		return "omscontact", true
	case 4162:
		return "omstopology", true
	case 4163:
		return "silverpeakpeer", true
	case 4164:
		return "silverpeakcomm", true
	case 4165:
		return "altcp", true
	case 4166:
		return "joost", true
	case 4167:
		return "ddgn", true
	case 4168:
		return "pslicser", true
	case 4169:
		return "iadt-disc", true
	case 4172:
		return "pcoip", true
	case 4173:
		return "mma-discovery", true
	case 4174:
		return "sm-disc", true
	case 4177:
		return "wello", true
	case 4178:
		return "storman", true
	case 4179:
		return "MaxumSP", true
	case 4180:
		return "httpx", true
	case 4181:
		return "macbak", true
	case 4182:
		return "pcptcpservice", true
	case 4183:
		return "cyborgnet", true
	case 4184:
		return "universe-suite", true
	case 4185:
		return "wcpp", true
	case 4188:
		return "vatata", true
	case 4191:
		return "dsmipv6", true
	case 4192:
		return "azeti-bd", true
	case 4195:
		return "aws-wsp", true
	case 4197:
		return "hctl", true
	case 4199:
		return "eims-admin", true
	case 4300:
		return "corelccam", true
	case 4301:
		return "d-data", true
	case 4302:
		return "d-data-control", true
	case 4303:
		return "srcp", true
	case 4304:
		return "owserver", true
	case 4305:
		return "batman", true
	case 4306:
		return "pinghgl", true
	case 4307:
		return "trueconf", true
	case 4308:
		return "compx-lockview", true
	case 4309:
		return "dserver", true
	case 4310:
		return "mirrtex", true
	case 4319:
		return "fox-skytale", true
	case 4320:
		return "fdt-rcatp", true
	case 4321:
		return "rwhois", true
	case 4322:
		return "trim-event", true
	case 4323:
		return "trim-ice", true
	case 4325:
		return "geognosisman", true
	case 4326:
		return "geognosis", true
	case 4327:
		return "jaxer-web", true
	case 4328:
		return "jaxer-manager", true
	case 4333:
		return "ahsp", true
	case 4340:
		return "gaia", true
	case 4341:
		return "lisp-data", true
	case 4342:
		return "lisp-control", true
	case 4343:
		return "unicall", true
	case 4344:
		return "vinainstall", true
	case 4345:
		return "m4-network-as", true
	case 4346:
		return "elanlm", true
	case 4347:
		return "lansurveyor", true
	case 4348:
		return "itose", true
	case 4349:
		return "fsportmap", true
	case 4350:
		return "net-device", true
	case 4351:
		return "plcy-net-svcs", true
	case 4352:
		return "pjlink", true
	case 4353:
		return "f5-iquery", true
	case 4354:
		return "qsnet-trans", true
	case 4355:
		return "qsnet-workst", true
	case 4356:
		return "qsnet-assist", true
	case 4357:
		return "qsnet-cond", true
	case 4358:
		return "qsnet-nucl", true
	case 4359:
		return "omabcastltkm", true
	case 4361:
		return "nacnl", true
	case 4362:
		return "afore-vdp-disc", true
	case 4366:
		return "shadowstream", true
	case 4368:
		return "wxbrief", true
	case 4369:
		return "epmd", true
	case 4370:
		return "elpro-tunnel", true
	case 4371:
		return "l2c-disc", true
	case 4372:
		return "l2c-data", true
	case 4373:
		return "remctl", true
	case 4375:
		return "tolteces", true
	case 4376:
		return "bip", true
	case 4377:
		return "cp-spxsvr", true
	case 4378:
		return "cp-spxdpy", true
	case 4379:
		return "ctdb", true
	case 4389:
		return "xandros-cms", true
	case 4390:
		return "wiegand", true
	case 4394:
		return "apwi-disc", true
	case 4395:
		return "omnivisionesx", true
	case 4400:
		return "ds-srv", true
	case 4401:
		return "ds-srvr", true
	case 4402:
		return "ds-clnt", true
	case 4403:
		return "ds-user", true
	case 4404:
		return "ds-admin", true
	case 4405:
		return "ds-mail", true
	case 4406:
		return "ds-slp", true
	case 4412:
		return "smallchat", true
	case 4413:
		return "avi-nms-disc", true
	case 4416:
		return "pjj-player-disc", true
	case 4418:
		return "axysbridge", true
	case 4420:
		return "nvme", true
	case 4425:
		return "netrockey6", true
	case 4426:
		return "beacon-port-2", true
	case 4430:
		return "rsqlserver", true
	case 4432:
		return "l-acoustics", true
	case 4441:
		return "netblox", true
	case 4442:
		return "saris", true
	case 4443:
		return "pharos", true
	case 4444:
		return "krb524", true
	case 4445:
		return "upnotifyp", true
	case 4446:
		return "n1-fwp", true
	case 4447:
		return "n1-rmgmt", true
	case 4448:
		return "asc-slmd", true
	case 4449:
		return "privatewire", true
	case 4450:
		return "camp", true
	case 4451:
		return "ctisystemmsg", true
	case 4452:
		return "ctiprogramload", true
	case 4453:
		return "nssalertmgr", true
	case 4454:
		return "nssagentmgr", true
	case 4455:
		return "prchat-user", true
	case 4456:
		return "prchat-server", true
	case 4457:
		return "prRegister", true
	case 4458:
		return "mcp", true
	case 4484:
		return "hpssmgmt", true
	case 4486:
		return "icms", true
	case 4488:
		return "awacs-ice", true
	case 4500:
		return "ipsec-nat-t", true
	case 4534:
		return "armagetronad", true
	case 4535:
		return "ehs", true
	case 4536:
		return "ehs-ssl", true
	case 4537:
		return "wssauthsvc", true
	case 4538:
		return "swx-gate", true
	case 4545:
		return "worldscores", true
	case 4546:
		return "sf-lm", true
	case 4547:
		return "lanner-lm", true
	case 4548:
		return "synchromesh", true
	case 4549:
		return "aegate", true
	case 4550:
		return "gds-adppiw-db", true
	case 4551:
		return "ieee-mih", true
	case 4552:
		return "menandmice-mon", true
	case 4554:
		return "msfrs", true
	case 4555:
		return "rsip", true
	case 4556:
		return "dtn-bundle", true
	case 4557:
		return "mtcevrunqss", true
	case 4558:
		return "mtcevrunqman", true
	case 4559:
		return "hylafax", true
	case 4566:
		return "kwtc", true
	case 4567:
		return "tram", true
	case 4568:
		return "bmc-reporting", true
	case 4569:
		return "iax", true
	case 4591:
		return "l3t-at-an", true
	case 4592:
		return "hrpd-ith-at-an", true
	case 4593:
		return "ipt-anri-anri", true
	case 4594:
		return "ias-session", true
	case 4595:
		return "ias-paging", true
	case 4596:
		return "ias-neighbor", true
	case 4597:
		return "a21-an-1xbs", true
	case 4598:
		return "a16-an-an", true
	case 4599:
		return "a17-an-an", true
	case 4600:
		return "piranha1", true
	case 4601:
		return "piranha2", true
	case 4621:
		return "ventoso", true
	case 4646:
		return "dots-signal", true
	case 4658:
		return "playsta2-app", true
	case 4659:
		return "playsta2-lob", true
	case 4660:
		return "smaclmgr", true
	case 4661:
		return "kar2ouche", true
	case 4662:
		return "oms", true
	case 4663:
		return "noteit", true
	case 4664:
		return "ems", true
	case 4665:
		return "contclientms", true
	case 4666:
		return "eportcomm", true
	case 4667:
		return "mmacomm", true
	case 4668:
		return "mmaeds", true
	case 4669:
		return "eportcommdata", true
	case 4670:
		return "light", true
	case 4671:
		return "acter", true
	case 4672:
		return "rfa", true
	case 4673:
		return "cxws", true
	case 4674:
		return "appiq-mgmt", true
	case 4675:
		return "dhct-status", true
	case 4676:
		return "dhct-alerts", true
	case 4677:
		return "bcs", true
	case 4678:
		return "traversal", true
	case 4679:
		return "mgesupervision", true
	case 4680:
		return "mgemanagement", true
	case 4681:
		return "parliant", true
	case 4682:
		return "finisar", true
	case 4683:
		return "spike", true
	case 4684:
		return "rfid-rp1", true
	case 4685:
		return "autopac", true
	case 4686:
		return "msp-os", true
	case 4687:
		return "nst", true
	case 4688:
		return "mobile-p2p", true
	case 4689:
		return "altovacentral", true
	case 4690:
		return "prelude", true
	case 4691:
		return "mtn", true
	case 4692:
		return "conspiracy", true
	case 4700:
		return "netxms-agent", true
	case 4701:
		return "netxms-mgmt", true
	case 4702:
		return "netxms-sync", true
	case 4711:
		return "trinity-dist", true
	case 4725:
		return "truckstar", true
	case 4726:
		return "a26-fap-fgw", true
	case 4727:
		return "fcis-disc", true
	case 4728:
		return "capmux", true
	case 4729:
		return "gsmtap", true
	case 4730:
		return "gearman", true
	case 4732:
		return "ohmtrigger", true
	case 4737:
		return "ipdr-sp", true
	case 4738:
		return "solera-lpn", true
	case 4739:
		return "ipfix", true
	case 4740:
		return "ipfixs", true
	case 4741:
		return "lumimgrd", true
	case 4742:
		return "sicct-sdp", true
	case 4743:
		return "openhpid", true
	case 4744:
		return "ifsp", true
	case 4745:
		return "fmp", true
	case 4746:
		return "intelliadm-disc", true
	case 4747:
		return "buschtrommel", true
	case 4749:
		return "profilemac", true
	case 4750:
		return "ssad", true
	case 4751:
		return "spocp", true
	case 4752:
		return "snap", true
	case 4753:
		return "simon-disc", true
	case 4754:
		return "gre-in-udp", true
	case 4755:
		return "gre-udp-dtls", true
	case 4784:
		return "bfd-multi-ctl", true
	case 4785:
		return "cncp", true
	case 4789:
		return "vxlan", true
	case 4790:
		return "vxlan-gpe", true
	case 4791:
		return "roce", true
	case 4792:
		return "unified-bus", true
	case 4800:
		return "iims", true
	case 4801:
		return "iwec", true
	case 4802:
		return "ilss", true
	case 4803:
		return "notateit-disc", true
	case 4804:
		return "aja-ntv4-disc", true
	case 4827:
		return "htcp", true
	case 4837:
		return "varadero-0", true
	case 4838:
		return "varadero-1", true
	case 4839:
		return "varadero-2", true
	case 4840:
		return "opcua-udp", true
	case 4841:
		return "quosa", true
	case 4842:
		return "gw-asv", true
	case 4843:
		return "opcua-tls", true
	case 4844:
		return "gw-log", true
	case 4845:
		return "wcr-remlib", true
	case 4846:
		return "contamac-icm", true
	case 4847:
		return "wfc", true
	case 4848:
		return "appserv-http", true
	case 4849:
		return "appserv-https", true
	case 4850:
		return "sun-as-nodeagt", true
	case 4851:
		return "derby-repli", true
	case 4867:
		return "unify-debug", true
	case 4868:
		return "phrelay", true
	case 4869:
		return "phrelaydbg", true
	case 4870:
		return "cc-tracking", true
	case 4871:
		return "wired", true
	case 4876:
		return "tritium-can", true
	case 4877:
		return "lmcs", true
	case 4878:
		return "inst-discovery", true
	case 4881:
		return "socp-t", true
	case 4882:
		return "socp-c", true
	case 4884:
		return "hivestor", true
	case 4885:
		return "abbs", true
	case 4894:
		return "lyskom", true
	case 4899:
		return "radmin-port", true
	case 4900:
		return "hfcs", true
	case 4914:
		return "bones", true
	case 4936:
		return "an-signaling", true
	case 4937:
		return "atsc-mh-ssc", true
	case 4940:
		return "eq-office-4940", true
	case 4941:
		return "eq-office-4941", true
	case 4942:
		return "eq-office-4942", true
	case 4949:
		return "munin", true
	case 4950:
		return "sybasesrvmon", true
	case 4951:
		return "pwgwims", true
	case 4952:
		return "sagxtsds", true
	case 4969:
		return "ccss-qmm", true
	case 4970:
		return "ccss-qsm", true
	case 4980:
		return "ctxs-vpp", true
	case 4986:
		return "mrip", true
	case 4987:
		return "smar-se-port1", true
	case 4988:
		return "smar-se-port2", true
	case 4989:
		return "parallel", true
	case 4990:
		return "busycal", true
	case 4991:
		return "vrt", true
	case 4999:
		return "hfcs-manager", true
	case 5000:
		return "commplex-main", true
	case 5001:
		return "commplex-link", true
	case 5002:
		return "rfe", true
	case 5003:
		return "fmpro-internal", true
	case 5004:
		return "avt-profile-1", true
	case 5005:
		return "avt-profile-2", true
	case 5006:
		return "wsm-server", true
	case 5007:
		return "wsm-server-ssl", true
	case 5008:
		return "synapsis-edge", true
	case 5009:
		return "winfs", true
	case 5010:
		return "telelpathstart", true
	case 5011:
		return "telelpathattack", true
	case 5012:
		return "nsp", true
	case 5013:
		return "fmpro-v6", true
	case 5014:
		return "onpsocket", true
	case 5020:
		return "zenginkyo-1", true
	case 5021:
		return "zenginkyo-2", true
	case 5022:
		return "mice", true
	case 5023:
		return "htuilsrv", true
	case 5024:
		return "scpi-telnet", true
	case 5025:
		return "scpi-raw", true
	case 5026:
		return "strexec-d", true
	case 5027:
		return "strexec-s", true
	case 5029:
		return "infobright", true
	case 5031:
		return "dmp", true
	case 5042:
		return "asnaacceler8db", true
	case 5043:
		return "swxadmin", true
	case 5044:
		return "lxi-evntsvc", true
	case 5046:
		return "vpm-udp", true
	case 5047:
		return "iscape", true
	case 5049:
		return "ivocalize", true
	case 5050:
		return "mmcc", true
	case 5051:
		return "ita-agent", true
	case 5052:
		return "ita-manager", true
	case 5053:
		return "rlm-disc", true
	case 5055:
		return "unot", true
	case 5056:
		return "intecom-ps1", true
	case 5057:
		return "intecom-ps2", true
	case 5058:
		return "locus-disc", true
	case 5059:
		return "sds", true
	case 5060:
		return "sip", true
	case 5061:
		return "sips", true
	case 5062:
		return "na-localise", true
	case 5064:
		return "ca-1", true
	case 5065:
		return "ca-2", true
	case 5066:
		return "stanag-5066", true
	case 5067:
		return "authentx", true
	case 5069:
		return "i-net-2000-npr", true
	case 5070:
		return "vtsas", true
	case 5071:
		return "powerschool", true
	case 5072:
		return "ayiya", true
	case 5073:
		return "tag-pm", true
	case 5074:
		return "alesquery", true
	case 5078:
		return "pixelpusher", true
	case 5079:
		return "cp-spxrpts", true
	case 5080:
		return "onscreen", true
	case 5081:
		return "sdl-ets", true
	case 5082:
		return "qcp", true
	case 5083:
		return "qfp", true
	case 5084:
		return "llrp", true
	case 5085:
		return "encrypted-llrp", true
	case 5092:
		return "magpie", true
	case 5093:
		return "sentinel-lm", true
	case 5094:
		return "hart-ip", true
	case 5099:
		return "sentlm-srv2srv", true
	case 5100:
		return "socalia", true
	case 5101:
		return "talarian-udp", true
	case 5102:
		return "oms-nonsecure", true
	case 5104:
		return "tinymessage", true
	case 5105:
		return "hughes-ap", true
	case 5111:
		return "taep-as-svc", true
	case 5112:
		return "pm-cmdsvr", true
	case 5116:
		return "emb-proj-cmd", true
	case 5120:
		return "barracuda-bbs", true
	case 5133:
		return "nbt-pc", true
	case 5136:
		return "minotaur-sa", true
	case 5137:
		return "ctsd", true
	case 5145:
		return "rmonitor-secure", true
	case 5150:
		return "atmp", true
	case 5151:
		return "esri-sde", true
	case 5152:
		return "sde-discovery", true
	case 5154:
		return "bzflag", true
	case 5155:
		return "asctrl-agent", true
	case 5164:
		return "vpa-disc", true
	case 5165:
		return "ife-icorp", true
	case 5166:
		return "winpcs", true
	case 5167:
		return "scte104", true
	case 5168:
		return "scte30", true
	case 5190:
		return "aol", true
	case 5191:
		return "aol-1", true
	case 5192:
		return "aol-2", true
	case 5193:
		return "aol-3", true
	case 5200:
		return "targus-getdata", true
	case 5201:
		return "targus-getdata1", true
	case 5202:
		return "targus-getdata2", true
	case 5203:
		return "targus-getdata3", true
	case 5223:
		return "hpvirtgrp", true
	case 5224:
		return "hpvirtctrl", true
	case 5225:
		return "hp-server", true
	case 5226:
		return "hp-status", true
	case 5227:
		return "perfd", true
	case 5234:
		return "eenet", true
	case 5235:
		return "galaxy-network", true
	case 5236:
		return "padl2sim", true
	case 5237:
		return "mnet-discovery", true
	case 5245:
		return "downtools-disc", true
	case 5246:
		return "capwap-control", true
	case 5247:
		return "capwap-data", true
	case 5248:
		return "caacws", true
	case 5249:
		return "caaclang2", true
	case 5250:
		return "soagateway", true
	case 5251:
		return "caevms", true
	case 5252:
		return "movaz-ssc", true
	case 5264:
		return "3com-njack-1", true
	case 5265:
		return "3com-njack-2", true
	case 5270:
		return "cartographerxmp", true
	case 5271:
		return "cuelink-disc", true
	case 5272:
		return "pk", true
	case 5282:
		return "transmit-port", true
	case 5298:
		return "presence", true
	case 5299:
		return "nlg-data", true
	case 5300:
		return "hacl-hb", true
	case 5301:
		return "hacl-gs", true
	case 5302:
		return "hacl-cfg", true
	case 5303:
		return "hacl-probe", true
	case 5304:
		return "hacl-local", true
	case 5305:
		return "hacl-test", true
	case 5306:
		return "sun-mc-grp", true
	case 5307:
		return "sco-aip", true
	case 5308:
		return "cfengine", true
	case 5309:
		return "jprinter", true
	case 5310:
		return "outlaws", true
	case 5312:
		return "permabit-cs", true
	case 5313:
		return "rrdp", true
	case 5314:
		return "opalis-rbt-ipc", true
	case 5315:
		return "hacl-poll", true
	case 5343:
		return "kfserver", true
	case 5344:
		return "xkotodrcp", true
	case 5349:
		return "stuns", true
	case 5350:
		return "pcp-multicast", true
	case 5351:
		return "pcp", true
	case 5352:
		return "dns-llq", true
	case 5353:
		return "mdns", true
	case 5354:
		return "mdnsresponder", true
	case 5355:
		return "llmnr", true
	case 5356:
		return "ms-smlbiz", true
	case 5357:
		return "wsdapi", true
	case 5358:
		return "wsdapi-s", true
	case 5359:
		return "ms-alerter", true
	case 5360:
		return "ms-sideshow", true
	case 5361:
		return "ms-s-sideshow", true
	case 5362:
		return "serverwsd2", true
	case 5363:
		return "net-projection", true
	case 5364:
		return "kdnet", true
	case 5397:
		return "stresstester", true
	case 5398:
		return "elektron-admin", true
	case 5399:
		return "securitychase", true
	case 5400:
		return "excerpt", true
	case 5401:
		return "excerpts", true
	case 5402:
		return "mftp", true
	case 5403:
		return "hpoms-ci-lstn", true
	case 5404:
		return "hpoms-dps-lstn", true
	case 5405:
		return "netsupport", true
	case 5406:
		return "systemics-sox", true
	case 5407:
		return "foresyte-clear", true
	case 5408:
		return "foresyte-sec", true
	case 5409:
		return "salient-dtasrv", true
	case 5410:
		return "salient-usrmgr", true
	case 5411:
		return "actnet", true
	case 5412:
		return "continuus", true
	case 5413:
		return "wwiotalk", true
	case 5414:
		return "statusd", true
	case 5415:
		return "ns-server", true
	case 5416:
		return "sns-gateway", true
	case 5417:
		return "sns-agent", true
	case 5418:
		return "mcntp", true
	case 5419:
		return "dj-ice", true
	case 5420:
		return "cylink-c", true
	case 5421:
		return "netsupport2", true
	case 5422:
		return "salient-mux", true
	case 5423:
		return "virtualuser", true
	case 5424:
		return "beyond-remote", true
	case 5425:
		return "br-channel", true
	case 5426:
		return "devbasic", true
	case 5427:
		return "sco-peer-tta", true
	case 5428:
		return "telaconsole", true
	case 5429:
		return "base", true
	case 5430:
		return "radec-corp", true
	case 5431:
		return "park-agent", true
	case 5432:
		return "postgresql", true
	case 5433:
		return "pyrrho", true
	case 5434:
		return "sgi-arrayd", true
	case 5435:
		return "sceanics", true
	case 5436:
		return "pmip6-cntl", true
	case 5437:
		return "pmip6-data", true
	case 5443:
		return "spss", true
	case 5450:
		return "tiepie-disc", true
	case 5453:
		return "surebox", true
	case 5454:
		return "apc-5454", true
	case 5455:
		return "apc-5455", true
	case 5456:
		return "apc-5456", true
	case 5461:
		return "silkmeter", true
	case 5462:
		return "ttl-publisher", true
	case 5463:
		return "ttlpriceproxy", true
	case 5464:
		return "quailnet", true
	case 5465:
		return "netops-broker", true
	case 5474:
		return "apsolab-rpc", true
	case 5500:
		return "fcp-addr-srvr1", true
	case 5501:
		return "fcp-addr-srvr2", true
	case 5502:
		return "fcp-srvr-inst1", true
	case 5503:
		return "fcp-srvr-inst2", true
	case 5504:
		return "fcp-cics-gw1", true
	case 5505:
		return "checkoutdb", true
	case 5506:
		return "amc", true
	case 5540:
		return "matter", true
	case 5553:
		return "sgi-eventmond", true
	case 5554:
		return "sgi-esphttp", true
	case 5555:
		return "personal-agent", true
	case 5556:
		return "freeciv", true
	case 5567:
		return "dof-dps-mc-sec", true
	case 5568:
		return "sdt", true
	case 5569:
		return "rdmnet-device", true
	case 5573:
		return "sdmmp", true
	case 5580:
		return "tmosms0", true
	case 5581:
		return "tmosms1", true
	case 5582:
		return "fac-restore", true
	case 5583:
		return "tmo-icon-sync", true
	case 5584:
		return "bis-web", true
	case 5585:
		return "bis-sync", true
	case 5597:
		return "ininmessaging", true
	case 5598:
		return "mctfeed", true
	case 5599:
		return "esinstall", true
	case 5600:
		return "esmmanager", true
	case 5601:
		return "esmagent", true
	case 5602:
		return "a1-msc", true
	case 5603:
		return "a1-bs", true
	case 5604:
		return "a3-sdunode", true
	case 5605:
		return "a4-sdunode", true
	case 5627:
		return "ninaf", true
	case 5628:
		return "htrust", true
	case 5629:
		return "symantec-sfdb", true
	case 5630:
		return "precise-comm", true
	case 5631:
		return "pcanywheredata", true
	case 5632:
		return "pcanywherestat", true
	case 5633:
		return "beorl", true
	case 5634:
		return "xprtld", true
	case 5670:
		return "zre-disc", true
	case 5671:
		return "amqps", true
	case 5672:
		return "amqp", true
	case 5673:
		return "jms", true
	case 5674:
		return "hyperscsi-port", true
	case 5675:
		return "v5ua", true
	case 5676:
		return "raadmin", true
	case 5677:
		return "questdb2-lnchr", true
	case 5678:
		return "rrac", true
	case 5679:
		return "dccm", true
	case 5680:
		return "auriga-router", true
	case 5681:
		return "ncxcp", true
	case 5682:
		return "brightcore", true
	case 5683:
		return "coap", true
	case 5684:
		return "coaps", true
	case 5687:
		return "gog-multiplayer", true
	case 5688:
		return "ggz", true
	case 5689:
		return "qmvideo", true
	case 5713:
		return "proshareaudio", true
	case 5714:
		return "prosharevideo", true
	case 5715:
		return "prosharedata", true
	case 5716:
		return "prosharerequest", true
	case 5717:
		return "prosharenotify", true
	case 5718:
		return "dpm", true
	case 5719:
		return "dpm-agent", true
	case 5720:
		return "ms-licensing", true
	case 5721:
		return "dtpt", true
	case 5722:
		return "msdfsr", true
	case 5723:
		return "omhs", true
	case 5724:
		return "omsdk", true
	case 5728:
		return "io-dist-group", true
	case 5729:
		return "openmail", true
	case 5730:
		return "unieng", true
	case 5741:
		return "ida-discover1", true
	case 5742:
		return "ida-discover2", true
	case 5743:
		return "watchdoc-pod", true
	case 5744:
		return "watchdoc", true
	case 5745:
		return "fcopy-server", true
	case 5746:
		return "fcopys-server", true
	case 5747:
		return "tunatic", true
	case 5748:
		return "tunalyzer", true
	case 5750:
		return "rscd", true
	case 5755:
		return "openmailg", true
	case 5757:
		return "x500ms", true
	case 5766:
		return "openmailns", true
	case 5767:
		return "s-openmail", true
	case 5768:
		return "openmailpxy", true
	case 5769:
		return "spramsca", true
	case 5770:
		return "spramsd", true
	case 5771:
		return "netagent", true
	case 5777:
		return "starfield-io", true
	case 5781:
		return "3par-evts", true
	case 5782:
		return "3par-mgmt", true
	case 5783:
		return "3par-mgmt-ssl", true
	case 5784:
		return "ibar", true
	case 5785:
		return "3par-rcopy", true
	case 5786:
		return "cisco-redu", true
	case 5787:
		return "waascluster", true
	case 5793:
		return "xtreamx", true
	case 5794:
		return "spdp", true
	case 5813:
		return "icmpd", true
	case 5814:
		return "spt-automation", true
	case 5859:
		return "wherehoo", true
	case 5863:
		return "ppsuitemsg", true
	case 5900:
		return "rfb", true
	case 5903:
		return "ff-ice", true
	case 5904:
		return "ag-swim", true
	case 5905:
		return "asmgcs", true
	case 5906:
		return "rpas-c2", true
	case 5907:
		return "dsd", true
	case 5908:
		return "ipsma", true
	case 5909:
		return "agma", true
	case 5910:
		return "ats-atn", true
	case 5911:
		return "ats-acars", true
	case 5912:
		return "ais-met", true
	case 5913:
		return "aoc-acars", true
	case 5963:
		return "indy", true
	case 5968:
		return "mppolicy-v5", true
	case 5969:
		return "mppolicy-mgr", true
	case 5984:
		return "couchdb", true
	case 5985:
		return "wsman", true
	case 5986:
		return "wsmans", true
	case 5987:
		return "wbem-rmi", true
	case 5988:
		return "wbem-http", true
	case 5989:
		return "wbem-https", true
	case 5990:
		return "wbem-exp-https", true
	case 5991:
		return "nuxsl", true
	case 5992:
		return "consul-insight", true
	case 5999:
		return "cvsup", true
	case 6064:
		return "ndl-ahp-svc", true
	case 6065:
		return "winpharaoh", true
	case 6066:
		return "ewctsp", true
	case 6069:
		return "trip", true
	case 6070:
		return "messageasap", true
	case 6071:
		return "ssdtp", true
	case 6072:
		return "diagnose-proc", true
	case 6073:
		return "directplay8", true
	case 6074:
		return "max", true
	case 6080:
		return "gue", true
	case 6081:
		return "geneve", true
	case 6082:
		return "p25cai", true
	case 6083:
		return "miami-bcast", true
	case 6085:
		return "konspire2b", true
	case 6086:
		return "pdtp", true
	case 6087:
		return "ldss", true
	case 6088:
		return "doglms-notify", true
	case 6100:
		return "synchronet-db", true
	case 6101:
		return "synchronet-rtc", true
	case 6102:
		return "synchronet-upd", true
	case 6103:
		return "rets", true
	case 6104:
		return "dbdb", true
	case 6105:
		return "primaserver", true
	case 6106:
		return "mpsserver", true
	case 6107:
		return "etc-control", true
	case 6108:
		return "sercomm-scadmin", true
	case 6109:
		return "globecast-id", true
	case 6110:
		return "softcm", true
	case 6111:
		return "spc", true
	case 6112:
		return "dtspcd", true
	case 6118:
		return "tipc", true
	case 6122:
		return "bex-webadmin", true
	case 6123:
		return "backup-express", true
	case 6124:
		return "pnbs", true
	case 6133:
		return "nbt-wol", true
	case 6140:
		return "pulsonixnls", true
	case 6141:
		return "meta-corp", true
	case 6142:
		return "aspentec-lm", true
	case 6143:
		return "watershed-lm", true
	case 6144:
		return "statsci1-lm", true
	case 6145:
		return "statsci2-lm", true
	case 6146:
		return "lonewolf-lm", true
	case 6147:
		return "montage-lm", true
	case 6148:
		return "ricardo-lm", true
	case 6149:
		return "tal-pod", true
	case 6160:
		return "ecmp-data", true
	case 6161:
		return "patrol-ism", true
	case 6162:
		return "patrol-coll", true
	case 6163:
		return "pscribe", true
	case 6200:
		return "lm-x", true
	case 6201:
		return "thermo-calc", true
	case 6209:
		return "qmtps", true
	case 6222:
		return "radmind", true
	case 6241:
		return "jeol-nsddp-1", true
	case 6242:
		return "jeol-nsddp-2", true
	case 6243:
		return "jeol-nsddp-3", true
	case 6244:
		return "jeol-nsddp-4", true
	case 6251:
		return "tl1-raw-ssl", true
	case 6252:
		return "tl1-ssh", true
	case 6253:
		return "crip", true
	case 6268:
		return "grid", true
	case 6269:
		return "grid-alt", true
	case 6300:
		return "bmc-grx", true
	case 6301:
		return "bmc-ctd-ldap", true
	case 6306:
		return "ufmp", true
	case 6315:
		return "scup-disc", true
	case 6316:
		return "abb-escp", true
	case 6317:
		return "nav-data", true
	case 6320:
		return "repsvc", true
	case 6321:
		return "emp-server1", true
	case 6322:
		return "emp-server2", true
	case 6324:
		return "hrd-ns-disc", true
	case 6343:
		return "sflow", true
	case 6346:
		return "gnutella-svc", true
	case 6347:
		return "gnutella-rtr", true
	case 6350:
		return "adap", true
	case 6355:
		return "pmcs", true
	case 6360:
		return "metaedit-mu", true
	case 6363:
		return "ndn", true
	case 6370:
		return "metaedit-se", true
	case 6382:
		return "metatude-mds", true
	case 6389:
		return "clariion-evr01", true
	case 6390:
		return "metaedit-ws", true
	case 6417:
		return "faxcomservice", true
	case 6419:
		return "svdrp-disc", true
	case 6420:
		return "nim-vdrshell", true
	case 6421:
		return "nim-wan", true
	case 6443:
		return "sun-sr-https", true
	case 6444:
		return "sge-qmaster", true
	case 6445:
		return "sge-execd", true
	case 6446:
		return "mysql-proxy", true
	case 6455:
		return "skip-cert-recv", true
	case 6456:
		return "skip-cert-send", true
	case 6464:
		return "ieee11073-20701", true
	case 6471:
		return "lvision-lm", true
	case 6480:
		return "sun-sr-http", true
	case 6481:
		return "servicetags", true
	case 6482:
		return "ldoms-mgmt", true
	case 6483:
		return "SunVTS-RMI", true
	case 6484:
		return "sun-sr-jms", true
	case 6485:
		return "sun-sr-iiop", true
	case 6486:
		return "sun-sr-iiops", true
	case 6487:
		return "sun-sr-iiop-aut", true
	case 6488:
		return "sun-sr-jmx", true
	case 6489:
		return "sun-sr-admin", true
	case 6500:
		return "boks", true
	case 6501:
		return "boks-servc", true
	case 6502:
		return "boks-servm", true
	case 6503:
		return "boks-clntd", true
	case 6505:
		return "badm-priv", true
	case 6506:
		return "badm-pub", true
	case 6507:
		return "bdir-priv", true
	case 6508:
		return "bdir-pub", true
	case 6509:
		return "mgcs-mfp-port", true
	case 6510:
		return "mcer-port", true
	case 6511:
		return "dccp-udp", true
	case 6514:
		return "syslog-tls", true
	case 6515:
		return "elipse-rec", true
	case 6543:
		return "lds-distrib", true
	case 6544:
		return "lds-dump", true
	case 6547:
		return "apc-6547", true
	case 6548:
		return "apc-6548", true
	case 6549:
		return "apc-6549", true
	case 6550:
		return "fg-sysupdate", true
	case 6551:
		return "sum", true
	case 6558:
		return "xdsxdm", true
	case 6566:
		return "sane-port", true
	case 6568:
		return "rp-reputation", true
	case 6579:
		return "affiliate", true
	case 6580:
		return "parsec-master", true
	case 6581:
		return "parsec-peer", true
	case 6582:
		return "parsec-game", true
	case 6583:
		return "joaJewelSuite", true
	case 6619:
		return "odette-ftps", true
	case 6620:
		return "kftp-data", true
	case 6621:
		return "kftp", true
	case 6622:
		return "mcftp", true
	case 6623:
		return "ktelnet", true
	case 6626:
		return "wago-service", true
	case 6627:
		return "nexgen", true
	case 6628:
		return "afesc-mc", true
	case 6629:
		return "nexgen-aux", true
	case 6633:
		return "cisco-vpath-tun", true
	case 6634:
		return "mpls-pm", true
	case 6635:
		return "mpls-udp", true
	case 6636:
		return "mpls-udp-dtls", true
	case 6653:
		return "openflow", true
	case 6657:
		return "palcom-disc", true
	case 6670:
		return "vocaltec-gold", true
	case 6671:
		return "p4p-portal", true
	case 6672:
		return "vision-server", true
	case 6673:
		return "vision-elmd", true
	case 6678:
		return "vfbp-disc", true
	case 6679:
		return "osaut", true
	case 6689:
		return "tsa", true
	case 6696:
		return "babel", true
	case 6699:
		return "babel-dtls", true
	case 6701:
		return "kti-icad-srvr", true
	case 6702:
		return "e-design-net", true
	case 6703:
		return "e-design-web", true
	case 6714:
		return "ibprotocol", true
	case 6715:
		return "fibotrader-com", true
	case 6767:
		return "bmc-perf-agent", true
	case 6768:
		return "bmc-perf-mgrd", true
	case 6769:
		return "adi-gxp-srvprt", true
	case 6770:
		return "plysrv-http", true
	case 6771:
		return "plysrv-https", true
	case 6784:
		return "bfd-lag", true
	case 6785:
		return "dgpf-exchg", true
	case 6786:
		return "smc-jmx", true
	case 6787:
		return "smc-admin", true
	case 6788:
		return "smc-http", true
	case 6790:
		return "hnmp", true
	case 6791:
		return "hnm", true
	case 6801:
		return "acnet", true
	case 6831:
		return "ambit-lm", true
	case 6841:
		return "netmo-default", true
	case 6842:
		return "netmo-http", true
	case 6850:
		return "iccrushmore", true
	case 6868:
		return "acctopus-st", true
	case 6888:
		return "muse", true
	case 6924:
		return "split-ping", true
	case 6935:
		return "ethoscan", true
	case 6936:
		return "xsmsvc", true
	case 6946:
		return "bioserver", true
	case 6951:
		return "otlp", true
	case 6961:
		return "jmact3", true
	case 6962:
		return "jmevt2", true
	case 6963:
		return "swismgr1", true
	case 6964:
		return "swismgr2", true
	case 6965:
		return "swistrap", true
	case 6966:
		return "swispol", true
	case 6969:
		return "acmsoda", true
	case 6980:
		return "qolyester", true
	case 6997:
		return "MobilitySrv", true
	case 6998:
		return "iatp-highpri", true
	case 6999:
		return "iatp-normalpri", true
	case 7000:
		return "afs3-fileserver", true
	case 7001:
		return "afs3-callback", true
	case 7002:
		return "afs3-prserver", true
	case 7003:
		return "afs3-vlserver", true
	case 7004:
		return "afs3-kaserver", true
	case 7005:
		return "afs3-volser", true
	case 7006:
		return "afs3-errors", true
	case 7007:
		return "afs3-bos", true
	case 7008:
		return "afs3-update", true
	case 7009:
		return "afs3-rmtsys", true
	case 7010:
		return "ups-onlinet", true
	case 7011:
		return "talon-disc", true
	case 7012:
		return "talon-engine", true
	case 7013:
		return "microtalon-dis", true
	case 7014:
		return "microtalon-com", true
	case 7015:
		return "talon-webserver", true
	case 7016:
		return "spg", true
	case 7017:
		return "grasp", true
	case 7019:
		return "doceri-view", true
	case 7020:
		return "dpserve", true
	case 7021:
		return "dpserveadmin", true
	case 7022:
		return "ctdp", true
	case 7023:
		return "ct2nmcs", true
	case 7024:
		return "vmsvc", true
	case 7025:
		return "vmsvc-2", true
	case 7030:
		return "op-probe", true
	case 7040:
		return "quest-disc", true
	case 7070:
		return "arcp", true
	case 7071:
		return "iwg1", true
	case 7072:
		return "iba-cfg-disc", true
	case 7080:
		return "empowerid", true
	case 7088:
		return "zixi-transport", true
	case 7095:
		return "jdp-disc", true
	case 7099:
		return "lazy-ptop", true
	case 7100:
		return "font-service", true
	case 7101:
		return "elcn", true
	case 7107:
		return "aes-x170", true
	case 7121:
		return "virprot-lm", true
	case 7128:
		return "scenidm", true
	case 7129:
		return "scenccs", true
	case 7161:
		return "cabsm-comm", true
	case 7162:
		return "caistoragemgr", true
	case 7163:
		return "cacsambroker", true
	case 7164:
		return "fsr", true
	case 7165:
		return "doc-server", true
	case 7166:
		return "aruba-server", true
	case 7169:
		return "ccag-pib", true
	case 7170:
		return "nsrp", true
	case 7171:
		return "drm-production", true
	case 7174:
		return "clutild", true
	case 7181:
		return "janus-disc", true
	case 7200:
		return "fodms", true
	case 7201:
		return "dlip", true
	case 7227:
		return "ramp", true
	case 7235:
		return "aspcoordination", true
	case 7244:
		return "frc-hicp-disc", true
	case 7262:
		return "cnap", true
	case 7272:
		return "watchme-7272", true
	case 7273:
		return "oma-rlp", true
	case 7274:
		return "oma-rlp-s", true
	case 7275:
		return "oma-ulp", true
	case 7276:
		return "oma-ilp", true
	case 7277:
		return "oma-ilp-s", true
	case 7278:
		return "oma-dcdocbs", true
	case 7279:
		return "ctxlic", true
	case 7280:
		return "itactionserver1", true
	case 7281:
		return "itactionserver2", true
	case 7282:
		return "mzca-alert", true
	case 7365:
		return "lcm-server", true
	case 7391:
		return "mindfilesys", true
	case 7392:
		return "mrssrendezvous", true
	case 7393:
		return "nfoldman", true
	case 7394:
		return "fse", true
	case 7395:
		return "winqedit", true
	case 7397:
		return "hexarc", true
	case 7400:
		return "rtps-discovery", true
	case 7401:
		return "rtps-dd-ut", true
	case 7402:
		return "rtps-dd-mt", true
	case 7410:
		return "ionixnetmon", true
	case 7411:
		return "daqstream", true
	case 7420:
		return "ipluminary", true
	case 7421:
		return "mtportmon", true
	case 7426:
		return "pmdmgr", true
	case 7427:
		return "oveadmgr", true
	case 7428:
		return "ovladmgr", true
	case 7429:
		return "opi-sock", true
	case 7430:
		return "xmpv7", true
	case 7431:
		return "pmd", true
	case 7437:
		return "faximum", true
	case 7443:
		return "oracleas-https", true
	case 7473:
		return "rise", true
	case 7491:
		return "telops-lmd", true
	case 7500:
		return "silhouette", true
	case 7501:
		return "ovbus", true
	case 7510:
		return "ovhpas", true
	case 7511:
		return "pafec-lm", true
	case 7542:
		return "saratoga", true
	case 7543:
		return "atul", true
	case 7544:
		return "nta-ds", true
	case 7545:
		return "nta-us", true
	case 7546:
		return "cfs", true
	case 7547:
		return "cwmp", true
	case 7548:
		return "tidp", true
	case 7549:
		return "nls-tl", true
	case 7550:
		return "cloudsignaling", true
	case 7560:
		return "sncp", true
	case 7566:
		return "vsi-omega", true
	case 7570:
		return "aries-kfinder", true
	case 7574:
		return "coherence-disc", true
	case 7588:
		return "sun-lm", true
	case 7606:
		return "mipi-debug", true
	case 7624:
		return "indi", true
	case 7627:
		return "soap-http", true
	case 7628:
		return "zen-pawn", true
	case 7629:
		return "xdas", true
	case 7633:
		return "pmdfmgt", true
	case 7648:
		return "cuseeme", true
	case 7663:
		return "rome", true
	case 7674:
		return "imqtunnels", true
	case 7675:
		return "imqtunnel", true
	case 7676:
		return "imqbrokerd", true
	case 7677:
		return "sun-user-https", true
	case 7680:
		return "ms-do", true
	case 7689:
		return "collaber", true
	case 7697:
		return "klio", true
	case 7707:
		return "sync-em7", true
	case 7708:
		return "scinet", true
	case 7720:
		return "medimageportal", true
	case 7724:
		return "nsdeepfreezectl", true
	case 7725:
		return "nitrogen", true
	case 7726:
		return "freezexservice", true
	case 7727:
		return "trident-data", true
	case 7728:
		return "osvr", true
	case 7734:
		return "smip", true
	case 7738:
		return "aiagent", true
	case 7741:
		return "scriptview", true
	case 7743:
		return "sstp-1", true
	case 7744:
		return "raqmon-pdu", true
	case 7747:
		return "prgp", true
	case 7777:
		return "cbt", true
	case 7778:
		return "interwise", true
	case 7779:
		return "vstat", true
	case 7781:
		return "accu-lmgr", true
	case 7784:
		return "s-bfd", true
	case 7786:
		return "minivend", true
	case 7787:
		return "popup-reminders", true
	case 7789:
		return "office-tools", true
	case 7794:
		return "q3ade", true
	case 7797:
		return "pnet-conn", true
	case 7798:
		return "pnet-enc", true
	case 7799:
		return "altbsdp", true
	case 7800:
		return "asr", true
	case 7801:
		return "ssp-client", true
	case 7802:
		return "vns-tp", true
	case 7810:
		return "rbt-wanopt", true
	case 7845:
		return "apc-7845", true
	case 7846:
		return "apc-7846", true
	case 7872:
		return "mipv6tls", true
	case 7880:
		return "pss", true
	case 7887:
		return "ubroker", true
	case 7900:
		return "mevent", true
	case 7901:
		return "tnos-sp", true
	case 7902:
		return "tnos-dp", true
	case 7903:
		return "tnos-dps", true
	case 7913:
		return "qo-secure", true
	case 7932:
		return "t2-drm", true
	case 7933:
		return "t2-brm", true
	case 7962:
		return "generalsync", true
	case 7967:
		return "supercell", true
	case 7979:
		return "micromuse-ncps", true
	case 7980:
		return "quest-vista", true
	case 7982:
		return "sossd-disc", true
	case 7998:
		return "usicontentpush", true
	case 7999:
		return "irdmi2", true
	case 8000:
		return "irdmi", true
	case 8001:
		return "vcom-tunnel", true
	case 8002:
		return "teradataordbms", true
	case 8003:
		return "mcreport", true
	case 8005:
		return "mxi", true
	case 8006:
		return "wpl-disc", true
	case 8007:
		return "warppipe", true
	case 8008:
		return "http-alt", true
	case 8017:
		return "cisco-cloudsec", true
	case 8019:
		return "qbdb", true
	case 8020:
		return "intu-ec-svcdisc", true
	case 8021:
		return "intu-ec-client", true
	case 8022:
		return "oa-system", true
	case 8023:
		return "arca-api", true
	case 8025:
		return "ca-audit-da", true
	case 8026:
		return "ca-audit-ds", true
	case 8027:
		return "papachi-p2p-srv", true
	case 8032:
		return "pro-ed", true
	case 8033:
		return "mindprint", true
	case 8034:
		return "vantronix-mgmt", true
	case 8040:
		return "ampify", true
	case 8041:
		return "enguity-xccetp", true
	case 8052:
		return "senomix01", true
	case 8053:
		return "senomix02", true
	case 8054:
		return "senomix03", true
	case 8055:
		return "senomix04", true
	case 8056:
		return "senomix05", true
	case 8057:
		return "senomix06", true
	case 8058:
		return "senomix07", true
	case 8059:
		return "senomix08", true
	case 8060:
		return "aero", true
	case 8074:
		return "gadugadu", true
	case 8080:
		return "http-alt", true
	case 8081:
		return "sunproxyadmin", true
	case 8082:
		return "us-cli", true
	case 8083:
		return "us-srv", true
	case 8086:
		return "d-s-n", true
	case 8087:
		return "simplifymedia", true
	case 8088:
		return "radan-http", true
	case 8097:
		return "sac", true
	case 8100:
		return "xprint-server", true
	case 8111:
		return "skynetflow", true
	case 8115:
		return "mtl8000-matrix", true
	case 8116:
		return "cp-cluster", true
	case 8118:
		return "privoxy", true
	case 8121:
		return "apollo-data", true
	case 8122:
		return "apollo-admin", true
	case 8128:
		return "paycash-online", true
	case 8129:
		return "paycash-wbp", true
	case 8130:
		return "indigo-vrmi", true
	case 8131:
		return "indigo-vbcp", true
	case 8132:
		return "dbabble", true
	case 8148:
		return "isdd", true
	case 8149:
		return "eor-game", true
	case 8160:
		return "patrol", true
	case 8161:
		return "patrol-snmp", true
	case 8182:
		return "vmware-fdm", true
	case 8184:
		return "itach", true
	case 8192:
		return "spytechphone", true
	case 8194:
		return "blp1", true
	case 8195:
		return "blp2", true
	case 8199:
		return "vvr-data", true
	case 8200:
		return "trivnet1", true
	case 8201:
		return "trivnet2", true
	case 8202:
		return "aesop", true
	case 8204:
		return "lm-perfworks", true
	case 8205:
		return "lm-instmgr", true
	case 8206:
		return "lm-dta", true
	case 8207:
		return "lm-sserver", true
	case 8208:
		return "lm-webwatcher", true
	case 8211:
		return "aruba-papi", true
	case 8230:
		return "rexecj", true
	case 8231:
		return "hncp-udp-port", true
	case 8232:
		return "hncp-dtls-port", true
	case 8243:
		return "synapse-nhttps", true
	case 8266:
		return "espeasy-p2p", true
	case 8276:
		return "ms-mcc", true
	case 8280:
		return "synapse-nhttp", true
	case 8282:
		return "libelle-disc", true
	case 8292:
		return "blp3", true
	case 8294:
		return "blp4", true
	case 8300:
		return "tmi", true
	case 8301:
		return "amberon", true
	case 8320:
		return "tnp-discover", true
	case 8321:
		return "tnp", true
	case 8322:
		return "garmin-marine", true
	case 8351:
		return "server-find", true
	case 8376:
		return "cruise-enum", true
	case 8377:
		return "cruise-swroute", true
	case 8378:
		return "cruise-config", true
	case 8379:
		return "cruise-diags", true
	case 8380:
		return "cruise-update", true
	case 8383:
		return "m2mservices", true
	case 8384:
		return "marathontp", true
	case 8400:
		return "cvd", true
	case 8401:
		return "sabarsd", true
	case 8402:
		return "abarsd", true
	case 8403:
		return "admind", true
	case 8416:
		return "espeech", true
	case 8417:
		return "espeech-rtp", true
	case 8433:
		return "aws-as2", true
	case 8442:
		return "cybro-a-bus", true
	case 8443:
		return "pcsync-https", true
	case 8444:
		return "pcsync-http", true
	case 8445:
		return "copy-disc", true
	case 8450:
		return "npmp", true
	case 8472:
		return "otv", true
	case 8473:
		return "vp2p", true
	case 8474:
		return "noteshare", true
	case 8500:
		return "fmtp", true
	case 8501:
		return "cmtp-av", true
	case 8503:
		return "lsp-self-ping", true
	case 8554:
		return "rtsp-alt", true
	case 8555:
		return "d-fence", true
	case 8567:
		return "dof-tunnel", true
	case 8600:
		return "asterix", true
	case 8609:
		return "canon-cpp-disc", true
	case 8610:
		return "canon-mfnp", true
	case 8611:
		return "canon-bjnp1", true
	case 8612:
		return "canon-bjnp2", true
	case 8613:
		return "canon-bjnp3", true
	case 8614:
		return "canon-bjnp4", true
	case 8675:
		return "msi-cps-rm-disc", true
	case 8686:
		return "sun-as-jmxrmi", true
	case 8732:
		return "dtp-net", true
	case 8733:
		return "ibus", true
	case 8763:
		return "mc-appserver", true
	case 8764:
		return "openqueue", true
	case 8765:
		return "ultraseek-http", true
	case 8766:
		return "amcs", true
	case 8770:
		return "dpap", true
	case 8786:
		return "msgclnt", true
	case 8787:
		return "msgsrvr", true
	case 8793:
		return "acd-pm", true
	case 8800:
		return "sunwebadmin", true
	case 8804:
		return "truecm", true
	case 8805:
		return "pfcp", true
	case 8807:
		return "hes-clip", true
	case 8808:
		return "ssports-bcast", true
	case 8809:
		return "3gpp-monp", true
	case 8873:
		return "dxspider", true
	case 8880:
		return "cddbp-alt", true
	case 8883:
		return "secure-mqtt", true
	case 8888:
		return "ddi-udp-1", true
	case 8889:
		return "ddi-udp-2", true
	case 8890:
		return "ddi-udp-3", true
	case 8891:
		return "ddi-udp-4", true
	case 8892:
		return "ddi-udp-5", true
	case 8893:
		return "ddi-udp-6", true
	case 8894:
		return "ddi-udp-7", true
	case 8899:
		return "ospf-lite", true
	case 8900:
		return "jmb-cds1", true
	case 8901:
		return "jmb-cds2", true
	case 8910:
		return "manyone-http", true
	case 8911:
		return "manyone-xml", true
	case 8912:
		return "wcbackup", true
	case 8913:
		return "dragonfly", true
	case 8954:
		return "cumulus-admin", true
	case 8980:
		return "nod-provider", true
	case 8981:
		return "nod-client", true
	case 8989:
		return "sunwebadmins", true
	case 8990:
		return "http-wmap", true
	case 8991:
		return "https-wmap", true
	case 8999:
		return "bctp", true
	case 9000:
		return "cslistener", true
	case 9001:
		return "etlservicemgr", true
	case 9002:
		return "dynamid", true
	case 9007:
		return "ogs-client", true
	case 9009:
		return "pichat", true
	case 9011:
		return "d-star", true
	case 9020:
		return "tambora", true
	case 9021:
		return "panagolin-ident", true
	case 9022:
		return "paragent", true
	case 9023:
		return "swa-1", true
	case 9024:
		return "swa-2", true
	case 9025:
		return "swa-3", true
	case 9026:
		return "swa-4", true
	case 9060:
		return "CardWeb-RT", true
	case 9080:
		return "glrpc", true
	case 9081:
		return "cisco-aqos", true
	case 9084:
		return "aurora", true
	case 9085:
		return "ibm-rsyscon", true
	case 9086:
		return "net2display", true
	case 9087:
		return "classic", true
	case 9088:
		return "sqlexec", true
	case 9089:
		return "sqlexec-ssl", true
	case 9090:
		return "websm", true
	case 9091:
		return "xmltec-xmlmail", true
	case 9092:
		return "XmlIpcRegSvc", true
	case 9100:
		return "hp-pdl-datastr", true
	case 9101:
		return "bacula-dir", true
	case 9102:
		return "bacula-fd", true
	case 9103:
		return "bacula-sd", true
	case 9104:
		return "peerwire", true
	case 9105:
		return "xadmin", true
	case 9106:
		return "astergate-disc", true
	case 9111:
		return "hexxorecore", true
	case 9119:
		return "mxit", true
	case 9131:
		return "dddp", true
	case 9160:
		return "apani1", true
	case 9161:
		return "apani2", true
	case 9162:
		return "apani3", true
	case 9163:
		return "apani4", true
	case 9164:
		return "apani5", true
	case 9191:
		return "sun-as-jpda", true
	case 9200:
		return "wap-wsp", true
	case 9201:
		return "wap-wsp-wtp", true
	case 9202:
		return "wap-wsp-s", true
	case 9203:
		return "wap-wsp-wtp-s", true
	case 9204:
		return "wap-vcard", true
	case 9205:
		return "wap-vcal", true
	case 9206:
		return "wap-vcard-s", true
	case 9207:
		return "wap-vcal-s", true
	case 9208:
		return "rjcdb-vcards", true
	case 9209:
		return "almobile-system", true
	case 9210:
		return "oma-mlp", true
	case 9211:
		return "oma-mlp-s", true
	case 9212:
		return "serverviewdbms", true
	case 9213:
		return "serverstart", true
	case 9214:
		return "ipdcesgbs", true
	case 9215:
		return "insis", true
	case 9216:
		return "acme", true
	case 9217:
		return "fsc-port", true
	case 9222:
		return "teamcoherence", true
	case 9255:
		return "mon", true
	case 9277:
		return "traingpsdata", true
	case 9278:
		return "pegasus", true
	case 9279:
		return "pegasus-ctl", true
	case 9280:
		return "pgps", true
	case 9281:
		return "swtp-port1", true
	case 9282:
		return "swtp-port2", true
	case 9283:
		return "callwaveiam", true
	case 9284:
		return "visd", true
	case 9285:
		return "n2h2server", true
	case 9286:
		return "n2receive", true
	case 9287:
		return "cumulus", true
	case 9292:
		return "armtechdaemon", true
	case 9293:
		return "storview", true
	case 9294:
		return "armcenterhttp", true
	case 9295:
		return "armcenterhttps", true
	case 9300:
		return "vrace", true
	case 9318:
		return "secure-ts", true
	case 9321:
		return "guibase", true
	case 9343:
		return "mpidcmgr", true
	case 9344:
		return "mphlpdmc", true
	case 9346:
		return "ctechlicensing", true
	case 9374:
		return "fjdmimgr", true
	case 9380:
		return "boxp", true
	case 9396:
		return "fjinvmgr", true
	case 9397:
		return "mpidcagt", true
	case 9400:
		return "sec-t4net-srv", true
	case 9401:
		return "sec-t4net-clt", true
	case 9402:
		return "sec-pc2fax-srv", true
	case 9418:
		return "git", true
	case 9443:
		return "tungsten-https", true
	case 9444:
		return "wso2esb-console", true
	case 9450:
		return "sntlkeyssrvr", true
	case 9500:
		return "ismserver", true
	case 9522:
		return "sma-spw", true
	case 9535:
		return "mngsuite", true
	case 9536:
		return "laes-bf", true
	case 9555:
		return "trispen-sra", true
	case 9592:
		return "ldgateway", true
	case 9593:
		return "cba8", true
	case 9594:
		return "msgsys", true
	case 9595:
		return "pds", true
	case 9596:
		return "mercury-disc", true
	case 9597:
		return "pd-admin", true
	case 9598:
		return "vscp", true
	case 9599:
		return "robix", true
	case 9600:
		return "micromuse-ncpw", true
	case 9612:
		return "streamcomm-ds", true
	case 9618:
		return "condor", true
	case 9628:
		return "odbcpathway", true
	case 9629:
		return "uniport", true
	case 9632:
		return "mc-comm", true
	case 9667:
		return "xmms2", true
	case 9668:
		return "tec5-sdctp", true
	case 9694:
		return "client-wakeup", true
	case 9695:
		return "ccnx", true
	case 9700:
		return "board-roar", true
	case 9747:
		return "l5nas-parchan", true
	case 9750:
		return "board-voip", true
	case 9753:
		return "rasadv", true
	case 9762:
		return "tungsten-http", true
	case 9800:
		return "davsrc", true
	case 9801:
		return "sstp-2", true
	case 9802:
		return "davsrcs", true
	case 9875:
		return "sapv1", true
	case 9878:
		return "kca-service", true
	case 9888:
		return "cyborg-systems", true
	case 9889:
		return "gt-proxy", true
	case 9898:
		return "monkeycom", true
	case 9899:
		return "sctp-tunneling", true
	case 9900:
		return "iua", true
	case 9901:
		return "enrp", true
	case 9903:
		return "multicast-ping", true
	case 9909:
		return "domaintime", true
	case 9911:
		return "sype-transport", true
	case 9950:
		return "apc-9950", true
	case 9951:
		return "apc-9951", true
	case 9952:
		return "apc-9952", true
	case 9953:
		return "acis", true
	case 9955:
		return "alljoyn-mcm", true
	case 9956:
		return "alljoyn", true
	case 9966:
		return "odnsp", true
	case 9987:
		return "dsm-scm-target", true
	case 9990:
		return "osm-appsrvr", true
	case 9991:
		return "osm-oev", true
	case 9992:
		return "palace-1", true
	case 9993:
		return "palace-2", true
	case 9994:
		return "palace-3", true
	case 9995:
		return "palace-4", true
	case 9996:
		return "palace-5", true
	case 9997:
		return "palace-6", true
	case 9998:
		return "distinct32", true
	case 9999:
		return "distinct", true
	case 10000:
		return "ndmp", true
	case 10001:
		return "scp-config", true
	case 10002:
		return "documentum", true
	case 10003:
		return "documentum-s", true
	case 10007:
		return "mvs-capacity", true
	case 10008:
		return "octopus", true
	case 10009:
		return "swdtp-sv", true
	case 10023:
		return "cefd-vmp", true
	case 10050:
		return "zabbix-agent", true
	case 10051:
		return "zabbix-trapper", true
	case 10080:
		return "amanda", true
	case 10081:
		return "famdc", true
	case 10100:
		return "itap-ddtp", true
	case 10101:
		return "ezmeeting-2", true
	case 10102:
		return "ezproxy-2", true
	case 10103:
		return "ezrelay", true
	case 10104:
		return "swdtp", true
	case 10107:
		return "bctp-server", true
	case 10110:
		return "nmea-0183", true
	case 10111:
		return "nmea-onenet", true
	case 10113:
		return "netiq-endpoint", true
	case 10114:
		return "netiq-qcheck", true
	case 10115:
		return "netiq-endpt", true
	case 10116:
		return "netiq-voipa", true
	case 10117:
		return "iqrm", true
	case 10128:
		return "bmc-perf-sd", true
	case 10160:
		return "qb-db-server", true
	case 10161:
		return "snmpdtls", true
	case 10162:
		return "snmpdtls-trap", true
	case 10200:
		return "trisoap", true
	case 10201:
		return "rscs", true
	case 10252:
		return "apollo-relay", true
	case 10253:
		return "eapol-relay", true
	case 10260:
		return "axis-wimp-port", true
	case 10288:
		return "blocks", true
	case 10439:
		return "bngsync", true
	case 10500:
		return "hip-nat-t", true
	case 10540:
		return "MOS-lower", true
	case 10541:
		return "MOS-upper", true
	case 10542:
		return "MOS-aux", true
	case 10543:
		return "MOS-soap", true
	case 10544:
		return "MOS-soap-opt", true
	case 10800:
		return "gap", true
	case 10805:
		return "lpdg", true
	case 10810:
		return "nmc-disc", true
	case 10860:
		return "helix", true
	case 10880:
		return "bveapi", true
	case 10990:
		return "rmiaux", true
	case 11000:
		return "irisa", true
	case 11001:
		return "metasys", true
	case 11095:
		return "weave", true
	case 11106:
		return "sgi-lk", true
	case 11108:
		return "myq-termlink", true
	case 11111:
		return "vce", true
	case 11112:
		return "dicom", true
	case 11161:
		return "suncacao-snmp", true
	case 11162:
		return "suncacao-jmxmp", true
	case 11163:
		return "suncacao-rmi", true
	case 11164:
		return "suncacao-csa", true
	case 11165:
		return "suncacao-websvc", true
	case 11171:
		return "snss", true
	case 11201:
		return "smsqp", true
	case 11208:
		return "wifree", true
	case 11211:
		return "memcache", true
	case 11319:
		return "imip", true
	case 11320:
		return "imip-channels", true
	case 11321:
		return "arena-server", true
	case 11367:
		return "atm-uhas", true
	case 11371:
		return "hkp", true
	case 11430:
		return "lsdp", true
	case 11600:
		return "tempest-port", true
	case 11720:
		return "h323callsigalt", true
	case 11723:
		return "emc-xsw-dcache", true
	case 11751:
		return "intrepid-ssl", true
	case 11796:
		return "lanschool-mpt", true
	case 11876:
		return "xoraya", true
	case 11877:
		return "x2e-disc", true
	case 11967:
		return "sysinfo-sp", true
	case 12000:
		return "entextxid", true
	case 12001:
		return "entextnetwk", true
	case 12002:
		return "entexthigh", true
	case 12003:
		return "entextmed", true
	case 12004:
		return "entextlow", true
	case 12005:
		return "dbisamserver1", true
	case 12006:
		return "dbisamserver2", true
	case 12007:
		return "accuracer", true
	case 12008:
		return "accuracer-dbms", true
	case 12009:
		return "ghvpn", true
	case 12012:
		return "vipera", true
	case 12013:
		return "vipera-ssl", true
	case 12109:
		return "rets-ssl", true
	case 12121:
		return "nupaper-ss", true
	case 12168:
		return "cawas", true
	case 12172:
		return "hivep", true
	case 12300:
		return "linogridengine", true
	case 12321:
		return "warehouse-sss", true
	case 12322:
		return "warehouse", true
	case 12345:
		return "italk", true
	case 12753:
		return "tsaf", true
	case 13160:
		return "i-zipqd", true
	case 13216:
		return "bcslogc", true
	case 13217:
		return "rs-pias", true
	case 13218:
		return "emc-vcas-udp", true
	case 13223:
		return "powwow-client", true
	case 13224:
		return "powwow-server", true
	case 13400:
		return "doip-disc", true
	case 13720:
		return "bprd", true
	case 13721:
		return "bpdbm", true
	case 13722:
		return "bpjava-msvc", true
	case 13724:
		return "vnetd", true
	case 13782:
		return "bpcd", true
	case 13783:
		return "vopied", true
	case 13785:
		return "nbdb", true
	case 13786:
		return "nomdb", true
	case 13818:
		return "dsmcc-config", true
	case 13819:
		return "dsmcc-session", true
	case 13820:
		return "dsmcc-passthru", true
	case 13821:
		return "dsmcc-download", true
	case 13822:
		return "dsmcc-ccp", true
	case 13894:
		return "ucontrol", true
	case 13929:
		return "dta-systems", true
	case 14000:
		return "scotty-ft", true
	case 14001:
		return "sua", true
	case 14002:
		return "scotty-disc", true
	case 14033:
		return "sage-best-com1", true
	case 14034:
		return "sage-best-com2", true
	case 14141:
		return "vcs-app", true
	case 14142:
		return "icpp", true
	case 14145:
		return "gcm-app", true
	case 14149:
		return "vrts-tdd", true
	case 14154:
		return "vad", true
	case 14250:
		return "cps", true
	case 14414:
		return "ca-web-update", true
	case 14936:
		return "hde-lcesrvr-1", true
	case 14937:
		return "hde-lcesrvr-2", true
	case 15000:
		return "hydap", true
	case 15118:
		return "v2g-secc", true
	case 15345:
		return "xpilot", true
	case 15363:
		return "3link", true
	case 15555:
		return "cisco-snat", true
	case 15660:
		return "bex-xr", true
	case 15740:
		return "ptp", true
	case 15998:
		return "2ping", true
	case 16003:
		return "alfin", true
	case 16161:
		return "sun-sea-port", true
	case 16309:
		return "etb4j", true
	case 16310:
		return "pduncs", true
	case 16311:
		return "pdefmns", true
	case 16360:
		return "netserialext1", true
	case 16361:
		return "netserialext2", true
	case 16367:
		return "netserialext3", true
	case 16368:
		return "netserialext4", true
	case 16384:
		return "connected", true
	case 16666:
		return "vtp", true
	case 16900:
		return "newbay-snc-mc", true
	case 16950:
		return "sgcip", true
	case 16991:
		return "intel-rci-mp", true
	case 16992:
		return "amt-soap-http", true
	case 16993:
		return "amt-soap-https", true
	case 16994:
		return "amt-redir-tcp", true
	case 16995:
		return "amt-redir-tls", true
	case 17007:
		return "isode-dua", true
	case 17185:
		return "soundsvirtual", true
	case 17219:
		return "chipper", true
	case 17220:
		return "avtp", true
	case 17221:
		return "avdecc", true
	case 17222:
		return "cpsp", true
	case 17224:
		return "trdp-pd", true
	case 17225:
		return "trdp-md", true
	case 17234:
		return "integrius-stp", true
	case 17235:
		return "ssh-mgmt", true
	case 17500:
		return "db-lsp-disc", true
	case 17729:
		return "ea", true
	case 17754:
		return "zep", true
	case 17755:
		return "zigbee-ip", true
	case 17756:
		return "zigbee-ips", true
	case 18000:
		return "biimenu", true
	case 18181:
		return "opsec-cvp", true
	case 18182:
		return "opsec-ufp", true
	case 18183:
		return "opsec-sam", true
	case 18184:
		return "opsec-lea", true
	case 18185:
		return "opsec-omi", true
	case 18186:
		return "ohsc", true
	case 18187:
		return "opsec-ela", true
	case 18241:
		return "checkpoint-rtm", true
	case 18262:
		return "gv-pf", true
	case 18463:
		return "ac-cluster", true
	case 18516:
		return "heythings", true
	case 18634:
		return "rds-ib", true
	case 18635:
		return "rds-ip", true
	case 18668:
		return "vdmmesh-disc", true
	case 18769:
		return "ique", true
	case 18881:
		return "infotos", true
	case 18888:
		return "apc-necmp", true
	case 19000:
		return "igrid", true
	case 19007:
		return "scintilla", true
	case 19191:
		return "opsec-uaa", true
	case 19194:
		return "ua-secureagent", true
	case 19220:
		return "cora-disc", true
	case 19283:
		return "keysrvr", true
	case 19315:
		return "keyshadow", true
	case 19398:
		return "mtrgtrans", true
	case 19410:
		return "hp-sco", true
	case 19411:
		return "hp-sca", true
	case 19412:
		return "hp-sessmon", true
	case 19539:
		return "fxuptp", true
	case 19540:
		return "sxuptp", true
	case 19541:
		return "jcp", true
	case 19788:
		return "mle", true
	case 19999:
		return "dnp-sec", true
	case 20000:
		return "dnp", true
	case 20001:
		return "microsan", true
	case 20002:
		return "commtact-http", true
	case 20003:
		return "commtact-https", true
	case 20005:
		return "openwebnet", true
	case 20012:
		return "ss-idi-disc", true
	case 20014:
		return "opendeploy", true
	case 20034:
		return "nburn-id", true
	case 20046:
		return "tmophl7mts", true
	case 20048:
		return "mountd", true
	case 20049:
		return "nfsrdma", true
	case 20167:
		return "tolfab", true
	case 20202:
		return "ipdtp-port", true
	case 20222:
		return "ipulse-ics", true
	case 20480:
		return "emwavemsg", true
	case 20670:
		return "track", true
	case 20999:
		return "athand-mmp", true
	case 21000:
		return "irtrans", true
	case 21554:
		return "dfserver", true
	case 21590:
		return "vofr-gateway", true
	case 21800:
		return "tvpm", true
	case 21845:
		return "webphone", true
	case 21846:
		return "netspeak-is", true
	case 21847:
		return "netspeak-cs", true
	case 21848:
		return "netspeak-acd", true
	case 21849:
		return "netspeak-cps", true
	case 22000:
		return "snapenetio", true
	case 22001:
		return "optocontrol", true
	case 22002:
		return "optohost002", true
	case 22003:
		return "optohost003", true
	case 22004:
		return "optohost004", true
	case 22005:
		return "optohost004", true
	case 22273:
		return "wnn6", true
	case 22305:
		return "cis", true
	case 22333:
		return "showcockpit-net", true
	case 22335:
		return "shrewd-stream", true
	case 22343:
		return "cis-secure", true
	case 22347:
		return "wibukey", true
	case 22350:
		return "codemeter", true
	case 22555:
		return "vocaltec-phone", true
	case 22763:
		return "talikaserver", true
	case 22800:
		return "aws-brf", true
	case 22951:
		return "brf-gw", true
	case 23000:
		return "inovaport1", true
	case 23001:
		return "inovaport2", true
	case 23002:
		return "inovaport3", true
	case 23003:
		return "inovaport4", true
	case 23004:
		return "inovaport5", true
	case 23005:
		return "inovaport6", true
	case 23272:
		return "s102", true
	case 23294:
		return "5afe-disc", true
	case 23333:
		return "elxmgmt", true
	case 23400:
		return "novar-dbase", true
	case 23401:
		return "novar-alarm", true
	case 23402:
		return "novar-global", true
	case 24000:
		return "med-ltp", true
	case 24001:
		return "med-fsp-rx", true
	case 24002:
		return "med-fsp-tx", true
	case 24003:
		return "med-supp", true
	case 24004:
		return "med-ovw", true
	case 24005:
		return "med-ci", true
	case 24006:
		return "med-net-svc", true
	case 24242:
		return "filesphere", true
	case 24249:
		return "vista-4gl", true
	case 24321:
		return "ild", true
	case 24322:
		return "hid", true
	case 24386:
		return "intel-rci", true
	case 24465:
		return "tonidods", true
	case 24554:
		return "binkp", true
	case 24577:
		return "bilobit-update", true
	case 24676:
		return "canditv", true
	case 24677:
		return "flashfiler", true
	case 24678:
		return "proactivate", true
	case 24680:
		return "tcc-http", true
	case 24850:
		return "assoc-disc", true
	case 24922:
		return "find", true
	case 25000:
		return "icl-twobase1", true
	case 25001:
		return "icl-twobase2", true
	case 25002:
		return "icl-twobase3", true
	case 25003:
		return "icl-twobase4", true
	case 25004:
		return "icl-twobase5", true
	case 25005:
		return "icl-twobase6", true
	case 25006:
		return "icl-twobase7", true
	case 25007:
		return "icl-twobase8", true
	case 25008:
		return "icl-twobase9", true
	case 25009:
		return "icl-twobase10", true
	case 25793:
		return "vocaltec-hos", true
	case 25900:
		return "tasp-net", true
	case 25901:
		return "niobserver", true
	case 25902:
		return "nilinkanalyst", true
	case 25903:
		return "niprobe", true
	case 25954:
		return "bf-game", true
	case 25955:
		return "bf-master", true
	case 26000:
		return "quake", true
	case 26133:
		return "scscp", true
	case 26208:
		return "wnn6-ds", true
	case 26260:
		return "ezproxy", true
	case 26261:
		return "ezmeeting", true
	case 26262:
		return "k3software-svr", true
	case 26263:
		return "k3software-cli", true
	case 26486:
		return "exoline-udp", true
	case 26487:
		return "exoconfig", true
	case 26489:
		return "exonet", true
	case 27345:
		return "imagepump", true
	case 27442:
		return "jesmsjc", true
	case 27504:
		return "kopek-httphead", true
	case 27782:
		return "ars-vista", true
	case 27999:
		return "tw-auth-key", true
	case 28000:
		return "nxlmd", true
	case 28119:
		return "a27-ran-ran", true
	case 28200:
		return "voxelstorm", true
	case 28240:
		return "siemensgsm", true
	case 29167:
		return "otmp", true
	case 30001:
		return "pago-services1", true
	case 30002:
		return "pago-services2", true
	case 30003:
		return "amicon-fpsu-ra", true
	case 30004:
		return "amicon-fpsu-s", true
	case 30260:
		return "kingdomsonline", true
	case 30832:
		return "samsung-disc", true
	case 30999:
		return "ovobs", true
	case 31016:
		return "ka-kdp", true
	case 31029:
		return "yawn", true
	case 31337:
		return "eldim", true
	case 31416:
		return "xqosd", true
	case 31457:
		return "tetrinet", true
	case 31620:
		return "lm-mon", true
	case 31765:
		return "gamesmith-port", true
	case 31948:
		return "iceedcp-tx", true
	case 31949:
		return "iceedcp-rx", true
	case 32034:
		return "iracinghelper", true
	case 32249:
		return "t1distproc60", true
	case 32483:
		return "apm-link", true
	case 32635:
		return "sec-ntb-clnt", true
	case 32636:
		return "DMExpress", true
	case 32767:
		return "filenet-powsrm", true
	case 32768:
		return "filenet-tms", true
	case 32769:
		return "filenet-rpc", true
	case 32770:
		return "filenet-nch", true
	case 32771:
		return "filenet-rmi", true
	case 32772:
		return "filenet-pa", true
	case 32773:
		return "filenet-cm", true
	case 32774:
		return "filenet-re", true
	case 32775:
		return "filenet-pch", true
	case 32776:
		return "filenet-peior", true
	case 32777:
		return "filenet-obrok", true
	case 32801:
		return "mlsn", true
	case 32896:
		return "idmgratm", true
	case 33123:
		return "aurora-balaena", true
	case 33331:
		return "diamondport", true
	case 33334:
		return "speedtrace-disc", true
	case 33434:
		return "traceroute", true
	case 33435:
		return "mtrace", true
	case 33656:
		return "snip-slave", true
	case 34249:
		return "turbonote-2", true
	case 34378:
		return "p-net-local", true
	case 34379:
		return "p-net-remote", true
	case 34567:
		return "edi_service", true
	case 34962:
		return "profinet-rt", true
	case 34963:
		return "profinet-rtm", true
	case 34964:
		return "profinet-cm", true
	case 34980:
		return "ethercat", true
	case 35001:
		return "rt-viewer", true
	case 35004:
		return "rt-classmanager", true
	case 35100:
		return "axio-disc", true
	case 35355:
		return "altova-lm-disc", true
	case 36001:
		return "allpeers", true
	case 36411:
		return "wlcp", true
	case 36865:
		return "kastenxpipe", true
	case 37475:
		return "neckar", true
	case 37654:
		return "unisys-eportal", true
	case 38002:
		return "crescoctrl-disc", true
	case 38201:
		return "galaxy7-data", true
	case 38202:
		return "fairview", true
	case 38203:
		return "agpolicy", true
	case 39681:
		return "turbonote-1", true
	case 40000:
		return "safetynetp", true
	case 40023:
		return "k-patentssensor", true
	case 40841:
		return "cscp", true
	case 40842:
		return "csccredir", true
	case 40843:
		return "csccfirewall", true
	case 40853:
		return "ortec-disc", true
	case 41111:
		return "fs-qos", true
	case 41230:
		return "z-wave-s", true
	case 41794:
		return "crestron-cip", true
	case 41795:
		return "crestron-ctp", true
	case 42508:
		return "candp", true
	case 42509:
		return "candrp", true
	case 42510:
		return "caerpc", true
	case 43000:
		return "recvr-rc-disc", true
	case 43188:
		return "reachout", true
	case 43189:
		return "ndm-agent-port", true
	case 43190:
		return "ip-provision", true
	case 43210:
		return "shaperai-disc", true
	case 43438:
		return "hmip-routing", true
	case 43439:
		return "eq3-config", true
	case 43440:
		return "ew-disc-cmd", true
	case 43441:
		return "ciscocsdb", true
	case 44321:
		return "pmcd", true
	case 44322:
		return "pmcdproxy", true
	case 44544:
		return "domiq", true
	case 44553:
		return "rbr-debug", true
	case 44600:
		return "asihpi", true
	case 44818:
		return "EtherNet-IP-2", true
	case 44900:
		return "m3da-disc", true
	case 45000:
		return "asmp-mon", true
	case 45054:
		return "invision-ag", true
	case 45514:
		return "cloudcheck-ping", true
	case 45678:
		return "eba", true
	case 45825:
		return "qdb2service", true
	case 45966:
		return "ssr-servermgr", true
	case 46999:
		return "mediabox", true
	case 47000:
		return "mbus", true
	case 47100:
		return "jvl-mactalk", true
	case 47557:
		return "dbbrowse", true
	case 47624:
		return "directplaysrvr", true
	case 47806:
		return "ap", true
	case 47808:
		return "bacnet", true
	case 47809:
		return "presonus-ucnet", true
	case 48000:
		return "nimcontroller", true
	case 48001:
		return "nimspooler", true
	case 48002:
		return "nimhub", true
	case 48003:
		return "nimgtw", true
	case 48128:
		return "isnetserv", true
	case 48129:
		return "blp5", true
	case 48556:
		return "com-bardac-dw", true
	case 48619:
		return "iqobject", true
	case 48653:
		return "robotraconteur", true
	case 49001:
		return "nusdp-disc", true

	}

	return "", false
}

// SCTPPortNames contains the port names for all SCTP ports.
func SCTPPortNames(port SCTPPort) (string, bool) {
	switch port {
	case 9:
		return "discard", true
	case 20:
		return "ftp-data", true
	case 21:
		return "ftp", true
	case 22:
		return "ssh", true
	case 80:
		return "http", true
	case 179:
		return "bgp", true
	case 443:
		return "https", true
	case 1021:
		return "exp1", true
	case 1022:
		return "exp2", true
	case 1167:
		return "cisco-ipsla", true
	case 1528:
		return "norp", true
	case 1720:
		return "h323hostcall", true
	case 2049:
		return "nfs", true
	case 2225:
		return "rcip-itu", true
	case 2904:
		return "m2ua", true
	case 2905:
		return "m3ua", true
	case 2944:
		return "megaco-h248", true
	case 2945:
		return "h248-binary", true
	case 3097:
		return "itu-bicc-stc", true
	case 3565:
		return "m2pa", true
	case 3863:
		return "asap-sctp", true
	case 3864:
		return "asap-sctp-tls", true
	case 3868:
		return "diameter", true
	case 4195:
		return "aws-wsp", true
	case 4333:
		return "ahsp", true
	case 4502:
		return "a25-fap-fgw", true
	case 4711:
		return "trinity-dist", true
	case 4739:
		return "ipfix", true
	case 4740:
		return "ipfixs", true
	case 5060:
		return "sip", true
	case 5061:
		return "sips", true
	case 5090:
		return "car", true
	case 5091:
		return "cxtp", true
	case 5215:
		return "noteza", true
	case 5445:
		return "smbdirect", true
	case 5672:
		return "amqp", true
	case 5675:
		return "v5ua", true
	case 5868:
		return "diameters", true
	case 5903:
		return "ff-ice", true
	case 5904:
		return "ag-swim", true
	case 5905:
		return "asmgcs", true
	case 5906:
		return "rpas-c2", true
	case 5907:
		return "dsd", true
	case 5908:
		return "ipsma", true
	case 5909:
		return "agma", true
	case 5910:
		return "cm", true
	case 5911:
		return "cpdlc", true
	case 5912:
		return "fis", true
	case 5913:
		return "ads-c", true
	case 6704:
		return "frc-hp", true
	case 6705:
		return "frc-mp", true
	case 6706:
		return "frc-lp", true
	case 6970:
		return "conductor-mpx", true
	case 7626:
		return "simco", true
	case 7701:
		return "nfapi", true
	case 7728:
		return "osvr", true
	case 8471:
		return "pim-port", true
	case 9082:
		return "lcs-ap", true
	case 9084:
		return "aurora", true
	case 9900:
		return "iua", true
	case 9901:
		return "enrp-sctp", true
	case 9902:
		return "enrp-sctp-tls", true
	case 11235:
		return "xcompute", true
	case 11997:
		return "wmereceiving", true
	case 11998:
		return "wmedistribution", true
	case 11999:
		return "wmereporting", true
	case 14001:
		return "sua", true
	case 19999:
		return "dnp-sec", true
	case 20000:
		return "dnp", true
	case 20049:
		return "nfsrdma", true
	case 25471:
		return "rna", true
	case 29118:
		return "sgsap", true
	case 29168:
		return "sbcap", true
	case 29169:
		return "iuhsctpassoc", true
	case 30100:
		return "rwp", true
	case 36412:
		return "s1-control", true
	case 36422:
		return "x2-control", true
	case 36423:
		return "slmap", true
	case 36424:
		return "nq-ap", true
	case 36443:
		return "m2ap", true
	case 36444:
		return "m3ap", true
	case 36462:
		return "xw-control", true
	case 37472:
		return "3gpp-w1ap", true
	case 38412:
		return "ng-control", true
	case 38422:
		return "xn-control", true
	case 38462:
		return "e1-interface", true
	case 38472:
		return "f1-control", true

	}

	return "", false
}
