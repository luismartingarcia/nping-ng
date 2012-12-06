# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, version detection, and the Nmap Scripting Engine.            *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
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
# * works of Nmap, as well as other software we distribute under this       *
# * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
# * but is meant to clarify our interpretation of derived works with some   *
# * common examples.  Our interpretation applies only to Nmap--we don't     *
# * speak for other people's GPL works.                                     *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@insecure.com for     *
# * further information.                                                    *
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
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
# *                                                                         *
# ***************************************************************************/

import os
import gtk
import gobject

from radialnet.bestwidgets.buttons import *
from radialnet.gui.SaveDialog import SaveDialog
from radialnet.gui.Dialogs import AboutDialog
from radialnet.gui.HostsViewer import HostsViewer
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog


SHOW = True
HIDE = False

REFRESH_RATE = 500



class ToolsMenu(gtk.Menu):
    """
    """
    def __init__(self, radialnet):
        """
        """
        gtk.Menu.__init__(self)

        self.radialnet = radialnet

        self.__create_items()


    def __create_items(self):
        """
        """
        self.__hosts = gtk.ImageMenuItem(_('Hosts viewer'))
        self.__hosts.connect("activate", self.__hosts_viewer_callback)
        self.__hosts_image = gtk.Image()
        self.__hosts_image.set_from_stock(gtk.STOCK_INDEX, gtk.ICON_SIZE_MENU)
        self.__hosts.set_image(self.__hosts_image)

        self.append(self.__hosts)

        self.__hosts.show_all()


    def __hosts_viewer_callback(self, widget):
        """
        """
        window = HostsViewer(self.radialnet.get_scanned_nodes())
        window.show_all()
        window.set_keep_above(True)


    def enable_dependents(self):
        """
        """
        self.__hosts.set_sensitive(True)


    def disable_dependents(self):
        """
        """
        self.__hosts.set_sensitive(False)



class Toolbar(gtk.HBox):
    """
    """
    def __init__(self, radialnet, window, control, fisheye):
        """
        """
        gtk.HBox.__init__(self)
        #self.set_style(gtk.TOOLBAR_BOTH_HORIZ)
        #self.set_tooltips(True)

        self.radialnet = radialnet

        self.__window = window
        self.__control_widget = control
        self.__fisheye_widget = fisheye

        self.__control_widget.show_all()
        self.__control_widget.set_no_show_all(True)
        self.__control_widget.hide()

        self.__fisheye_widget.show_all()
        self.__fisheye_widget.set_no_show_all(True)
        self.__fisheye_widget.hide()

        self.__save_chooser = None

        self.__create_widgets()


    def __create_widgets(self):
        """
        """
        # self.__tooltips = gtk.Tooltips()

        #self.__tools_menu = ToolsMenu(self.radialnet)

        #self.__tools_button = gtk.MenuToolButton(gtk.STOCK_PREFERENCES)
        #self.__tools_button.set_label(_('Tools'))
        #self.__tools_button.set_is_important(True)
        #self.__tools_button.set_menu(self.__tools_menu)
        #self.__tools_button.connect('clicked', self.__tools_callback)

        self.__save_button = BWStockButton(gtk.STOCK_SAVE, _("Save Graphic"))
        self.__save_button.connect("clicked", self.__save_image_callback)

        self.__hosts_button = BWStockButton(gtk.STOCK_INDEX, _("Hosts Viewer"))
        self.__hosts_button.connect("clicked", self.__hosts_viewer_callback)

        self.__control = BWToggleStockButton(gtk.STOCK_PROPERTIES, _("Controls"))
        self.__control.connect('clicked', self.__control_callback)
        self.__control.set_active(False)

        self.__fisheye = BWToggleStockButton(gtk.STOCK_ZOOM_FIT, _("Fisheye"))
        self.__fisheye.connect('clicked', self.__fisheye_callback)
        self.__fisheye.set_active(False)

        #self.__fullscreen = gtk.ToggleToolButton(gtk.STOCK_FULLSCREEN)
        #self.__fullscreen.set_label(_('Fullscreen'))
        #self.__fullscreen.set_is_important(True)
        #self.__fullscreen.connect('clicked', self.__fullscreen_callback)
        #self.__fullscreen.set_tooltip(self.__tooltips, _('Toggle fullscreen'))

        #self.__about = gtk.ToolButton(gtk.STOCK_ABOUT)
        #self.__about.set_label(_('About'))
        #self.__about.set_is_important(True)
        #self.__about.connect('clicked', self.__about_callback)
        #self.__about.set_tooltip(self.__tooltips, _('About RadialNet'))

        self.__separator = gtk.SeparatorToolItem()
        self.__expander = gtk.SeparatorToolItem()
        self.__expander.set_expand(True)
        self.__expander.set_draw(False)

        #self.insert(self.__open,         0)
        #self.insert(self.__separator,    1)
        #self.insert(self.__tools_button, 2)
        #self.insert(self.__expander,     3)
        #self.insert(self.__control,      4)
        #self.insert(self.__fisheye,      5)
        #self.insert(self.__fullscreen,   6)
        #self.insert(self.__about,        7)

        #self.pack_start(self.__tools_button, False)
        self.pack_start(self.__hosts_button, False)
        self.pack_start(self.__fisheye, False)
        self.pack_start(self.__control, False)
        self.pack_end(self.__save_button, False)


    def disable_controls(self):
        """
        """
        self.__control.set_sensitive(False)
        self.__fisheye.set_sensitive(False)
        self.__hosts_button.set_sensitive(False)
        #self.__tools_menu.disable_dependents()


    def enable_controls(self):
        """
        """
        self.__control.set_sensitive(True)
        self.__fisheye.set_sensitive(True)
        self.__hosts_button.set_sensitive(True)
        #self.__tools_menu.enable_dependents()


    def __tools_callback(self, widget):
        """
        """
        self.__tools_menu.popup(None, None, None, 1, 0)


    def __hosts_viewer_callback(self, widget):
        """
        """
        window = HostsViewer(self.radialnet.get_scanned_nodes())
        window.show_all()
        window.set_keep_above(True)


    def __save_image_callback(self, widget):
        """
        """
        if self.__save_chooser is None:
            self.__save_chooser = SaveDialog()

        response = self.__save_chooser.run()

        if response == gtk.RESPONSE_OK:
            filename = self.__save_chooser.get_filename()
            filetype = self.__save_chooser.get_filetype()

            try:
                self.radialnet.save_drawing_to_file(filename, filetype)
            except Exception, e:
                alert = HIGAlertDialog(parent=self.__save_chooser,
                        type=gtk.MESSAGE_ERROR,
                        message_format=_("Error saving snapshot"),
                        secondary_text=unicode(e))
                alert.run()
                alert.destroy()

        self.__save_chooser.hide()


    def __control_callback(self, widget=None):
        """
        """
        if self.__control.get_active():
            self.__control_widget.show()

        else:
            self.__control_widget.hide()


    def __fisheye_callback(self, widget=None):
        """
        """
        if not self.radialnet.is_in_animation():

            if self.__fisheye.get_active():

                self.__fisheye_widget.active_fisheye()
                self.__fisheye_widget.show()

            else:

                self.__fisheye_widget.deactive_fisheye()
                self.__fisheye_widget.hide()


    def __about_callback(self, widget):
        """
        """
        self.__about_dialog = AboutDialog()
        self.__about_dialog.show_all()


    def __fullscreen_callback(self, widget=None):
        """
        """
        if self.__fullscreen.get_active():
            self.__window.fullscreen()

        else:
            self.__window.unfullscreen()

