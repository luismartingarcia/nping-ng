#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

import gtk

from zenmapGUI.ScanToolbar import *
from zenmapCore.NetworkInventory import NetworkInventory
from zenmapCore.UmitConf import CommandProfile, ProfileNotFound
from zenmapCore.NmapCommand import NmapCommand
from zenmapCore.NmapParser import NmapParser

from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog
from zenmapGUI.higwidgets.higbuttons import HIGButton, HIGToggleButton
from zenmapGUI.higwidgets.higwindows import HIGWindow

from radialnet.core.XMLHandler import XMLReader
from radialnet.gui.RadialNet import *
from radialnet.gui.ControlWidget import *
from radialnet.gui.Toolbar import Toolbar
from radialnet.bestwidgets.boxes import *
from radialnet.bestwidgets.windows import *
from radialnet.util.integration import make_graph_from_hosts


SLOW_LIMIT = 1000

class TopologyPage(HIGVBox):
    def __init__(self, inventory):
        HIGVBox.__init__(self)

        self.set_border_width(6)
        self.set_spacing(4)

        self.network_inventory = inventory

        self._create_widgets()
        self._pack_widgets()

    def _create_widgets(self):
        self.rn_hbox = gtk.HBox()
        self.rn_hbox.set_spacing(4)
        self.rn_vbox = gtk.VBox()

        # RadialNet's widgets
        self.radialnet = RadialNet(LAYOUT_WEIGHTED)
        self.control = ControlWidget(self.radialnet)
        self.fisheye = ControlFisheye(self.radialnet)
        self.rn_toolbar = Toolbar(self.radialnet,
                               self,
                               self.control,
                               self.fisheye)

        self.display_panel = HIGVBox()

        self.radialnet.set_no_show_all(True)

        self.slow_vbox = HIGVBox()
        self.slow_label = gtk.Label()
        self.slow_vbox.pack_start(self.slow_label, False, False)
        show_button = gtk.Button(_("Show the topology anyway"))
        show_button.connect("clicked", self.show_anyway)
        self.slow_vbox.pack_start(show_button, False, False)
        self.slow_vbox.show_all()
        self.slow_vbox.set_no_show_all(True)
        self.slow_vbox.hide()

        self.radialnet.show()

    def _pack_widgets(self):
        self.rn_hbox.pack_start(self.display_panel, True, True)
        self.rn_hbox.pack_start(self.control, False)

        self.rn_vbox.pack_start(self.rn_hbox, True, True)
        self.rn_vbox.pack_start(self.fisheye, False)

        self.pack_start(self.rn_toolbar, False, False)
        self.pack_start(self.rn_vbox, True, True)

        self.display_panel.pack_start(self.slow_vbox, True, False)
        self.display_panel.pack_start(self.radialnet, True, True)

    def add_scan(self, scan):
        """Parses a given XML file and adds the parsed result to the network inventory."""
        self.network_inventory.add_scan(scan)
        self.update_radialnet()

    def update_radialnet(self):
        """Creates a graph from network inventory's host list and displays it."""
        hosts_up = self.network_inventory.get_hosts_up()

        self.slow_label.set_text(_("""\
Topology is disabled because too many hosts can cause it
to run slowly. The limit is %d hosts and there are %d.\
""" % (SLOW_LIMIT, len(hosts_up))))

        if len(hosts_up) <= SLOW_LIMIT:
            self.radialnet.show()
            self.slow_vbox.hide()
            self.update_radialnet_unchecked()
        else:
            self.radialnet.hide()
            self.slow_vbox.show()

    def update_radialnet_unchecked(self):
        hosts_up = self.network_inventory.get_hosts_up()
        graph = make_graph_from_hosts(hosts_up)
        self.radialnet.set_empty()
        self.radialnet.set_graph(graph)
        self.radialnet.show()

    def show_anyway(self, widget):
        self.radialnet.show()
        self.slow_vbox.hide()
        self.update_radialnet_unchecked()
