"""
Plugin that attempts to enumerate the array of pointers SrvTransaction2DispatchTable from the srv.sys driver.
Useful to identify the NSA implant DoublePulsar. 
 
@author:       Borja Merino
@license:      GNU General Public License 2.0
@contact:      bmerinofe@mgmail.com

Dependencies:
    construct:  pip install construct==2.5.5-reupload
    pdbparse:   pip install pdbparse
    pefile:    pip install pefile
    requests:    pip install requests
    cabextract:    apt-get install cabextract

References:
    [1] Geir Skjotskift (2017). Volatility memory forensics plugin for extracting Windows DNS Cache:
        https://github.com/mnemonic-no/dnscache
    [2] Carl Pulley (2013). PLugin designed to resolve addresses or symbol names:
        https://github.com/carlpulley/volatility/blob/master/symbols.py

"""

from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.win32 as win32
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.obj as obj
import struct
import pdbparse
import pdbparse.peinfo
import requests
import shutil
import subprocess
import logging
import os

#TODO trouver ou ce fait la comparaison entre PDB et RAM
class DoublePulsar(common.AbstractWindowsCommand):
    """Show the array of pointers SrvTransaction2DispatchTable from srv.sys (useful to detect the DoublePulsar implant)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP_DIR', short_option='D', default=None,
                          help='Dump directory for the .pdb file',
                          action='store')
        config.add_option("SYMBOLS", short_option='S', default="http://msdl.microsoft.com/download/symbols",
                          help="Server to download the .pdb file from", action='store')
        config.add_option("PDB_FILE", default=None,
                          help="Path to the .pdb file",
                          action="store")
        config.add_option('PROXY', default=None,
                          help='Proxy server to download .PDB file',
                          action='store')
        config.add_option("CABEXTRACT", default="cabextract",
                          help="Path to cabextract utility",
                          action="store")

    # Taken from malware/idt.py
    def _get_section_name(self, mod, addr):
        try:
            dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = mod.DllBase, vm = mod.obj_vm)
            nt_header = dos_header.get_nt_header()
        except (ValueError, exceptions.SanityCheckException):
            return ''
        for sec in nt_header.get_sections():
            if (addr > mod.DllBase + sec.VirtualAddress and
                    addr < sec.Misc.VirtualSize + (mod.DllBase + sec.VirtualAddress)):
                return str(sec.Name or '')
        return ''

    def _get_debug_symbols(self, addr_space, mod):
        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()
        debug_data = addr_space.zread(image_base + debug_dir.AddressOfRawData, debug_dir.SizeOfData)
        if debug_data[:4] == 'RSDS':
            return pdbparse.peinfo.get_rsds(debug_data)
        else:
            return ''

    # Useful code: https://github.com/mnemonic-no/dnscache/blob/master/dnscache.py
    def _download_pdb_file(self, guid, filename):
        archive = filename
        url = "{0}/{1}/{2}/{3}".format(self._config.SYMBOLS, filename, guid, archive)
        proxies = None
        if self._config.PROXY:
            proxies = {
                    'http': os.environ['http_proxy'],
                    'https': os.environ['https_proxy']
                    }
        logging.getLogger("requests").setLevel(logging.WARNING)
        resp = requests.get(url, proxies=proxies, stream=True)
        if resp.status_code != 200:
            return None
        archive_path = os.path.join('/tmp/', archive)
        with open(archive_path, "wb") as af:
            shutil.copyfileobj(resp.raw, af)
        fh = open("NUL","w")
        subprocess.call([self._config.CABEXTRACT, archive_path, "-d", '/tmp/'], stdout = fh, stderr = fh)
        fh.close()
        return os.path.join('/tmp/', filename)

    # Useful code: https://github.com/carlpulley/volatility/blob/master/symbols.py
    def _get_srvtrans_symbol(self, pdbfile, imgbase):
        pdb = pdbparse.parse(pdbfile, fast_load=True)
        pdb.STREAM_DBI.load()
        pdb._update_names()
        pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
        pdb.STREAM_GSYM.load()
        pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
        pdb.STREAM_OMAP_FROM_SRC.load()
        pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
        pdb.STREAM_SECT_HDR_ORIG.load()
        sects = pdb.STREAM_SECT_HDR_ORIG.sections
        omap = pdb.STREAM_OMAP_FROM_SRC
        gsyms = pdb.STREAM_GSYM
        srv_trans_pointer = "SrvTransaction2DispatchTable"#Addr SrvTransaction2DispatchTable 120672 -> aucune trace avec yarascan => addr 0xfffff8800477c760
#In [5]: db(0xfffff8800477c760)
#0xfffff8800477c760  60 60 7e 04 80 f8 ff ff 90 0d 7b 04 80 f8 ff ff   ``~.......{..... << addr de srvsmbopen2
#0xfffff8800477c770  20 38 7e 04 80 f8 ff ff c0 28 7b 04 80 f8 ff ff   .8~......({.....
#0xfffff8800477c780  00 86 7d 04 80 f8 ff ff e0 08 7b 04 80 f8 ff ff   ..}.......{.....
#0xfffff8800477c790  90 65 7e 04 80 f8 ff ff f0 9b 7a 04 80 f8 ff ff   .e~.......z.....
#0xfffff8800477c7a0  10 e3 7a 04 80 f8 ff ff 20 cd 7c 04 80 f8 ff ff   ..z.......|.....
#0xfffff8800477c7b0  c0 63 7e 04 80 f8 ff ff 20 cd 7c 04 80 f8 ff ff   .c~.......|.....
#0xfffff8800477c7c0  20 cd 7c 04 80 f8 ff ff d0 8d 7d 04 80 f8 ff ff   ..|.......}.....
#0xfffff8800477c7d0  20 cb 7c 04 80 f8 ff ff 20 cb 7c 04 80 f8 ff ff   ..|.......|.....

        #srv_trans_pointer = "SrvSmbOpen2" # addr srvsmbopen2 553056 => addr 0xfffff880047e6060
#In [7]: db(0xfffff880047e6060)
#0xfffff880047e6060  48 8b c4 53 55 56 57 41 54 41 55 41 56 41 57 48   H..SUVWATAUAVAWH
#0xfffff880047e6070  83 ec 68 45 33 ff 48 8b d9 45 8d 77 01 44 89 78   ..hE3.H..E.w.D.x
#0xfffff880047e6080  10 45 0f b7 ef 66 44 89 78 08 44 84 b1 18 02 00   .E...fD.x.D.....
#0xfffff880047e6090  00 75 07 c6 81 51 02 00 00 35 44 39 35 23 6e f9   .u...Q...5D95#n.
#0xfffff880047e60a0  ff 72 05 e8 a8 76 f8 ff 48 8b b3 08 01 00 00 44   .r...v..H......D
#0xfffff880047e60b0  8b 8e 98 00 00 00 4c 8b 66 70 48 8b 6e 78 41 83   ......L.fpH.nxA.
#0xfffff880047e60c0  f9 1d 0f 82 52 02 00 00 83 be a0 00 00 00 1e 0f   ....R...........
#0xfffff880047e60d0  82 45 02 00 00 44 89 bc 24 b8 00 00 00 44 8b 86   .E...D..$....D..
#On voit que c'est une fonction:
#In [8]: dis(0xfffff880047e6060)
#0xfffff880047e6060 488bc4                           MOV RAX, RSP
#0xfffff880047e6063 53                               PUSH RBX
#0xfffff880047e6064 55                               PUSH RBP
#0xfffff880047e6065 56                               PUSH RSI
#0xfffff880047e6066 57                               PUSH RDI
#0xfffff880047e6067 4154                             PUSH R12
#0xfffff880047e6069 4155                             PUSH R13
#0xfffff880047e606b 4156                             PUSH R14
#0xfffff880047e606d 4157                             PUSH R15
#0xfffff880047e606f 4883ec68                         SUB RSP, 0x68
#0xfffff880047e6073 4533ff                           XOR R15D, R15D
#0xfffff880047e6076 488bd9                           MOV RBX, RCX
#0xfffff880047e6079 458d7701                         LEA R14D, [R15+0x1]
#0xfffff880047e607d 44897810                         MOV [RAX+0x10], R15D
#0xfffff880047e6081 450fb7ef                         MOVZX R13D, R15W
#0xfffff880047e6085 6644897808                       MOV [RAX+0x8], R15W
#0xfffff880047e608a 4484b118020000                   TEST [RCX+0x218], R14B
#0xfffff880047e6091 7507                             JNZ 0xfffff880047e609a
#0xfffff880047e6093 c6815102000035                   MOV BYTE [RCX+0x251], 0x35
#0xfffff880047e609a 443935236ef9ff                   CMP [RIP-0x691dd], R14D
#0xfffff880047e60a1 7205                             JB 0xfffff880047e60a8
#0xfffff880047e60a3 e8a876f8ff                       CALL 0xfffff8800476d750
#!!!!! Voir sur en dessous on peut retrouver le type des symbol: fonction, table, .... ce qui permettrait d'identifier toutes les tables et de verifier que ce qu'elles contiennent est bien normale, voir aussi si on peut avoir l'information de la taille de la table dans le pdb
        for sym in gsyms.globals:
            if srv_trans_pointer.lower() == sym.name.lower(): #remplace == paar in
                virt_base = sects[sym.segment-1].VirtualAddress
                sym_rva = omap.remap(sym.offset + virt_base)
                return sym_rva    
        return ''

    def _get_srv(self, addr_space):
        modules = win32.modules.lsmod(addr_space)
        for module in modules:
            if str(module.BaseDllName) == "srv.sys":
                return module
                break
        return ''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        if addr_space.profile.metadata.get("memory_model", "") == "32bit":
            inc = 4
        else:
            inc = 8
        srv_module = self._get_srv(addr_space)#trouve adresse de srv.sys
        if not srv_module:
            debug.error("Driver srv.sys not found.")
            return
        if not self._config.PDB_FILE:
            guid, pdb = self._get_debug_symbols(addr_space, srv_module) #recgerche les symbol sur le reel et met dans pdb
            pdb_file = self._download_pdb_file(guid, pdb) # telecharge pdb
            if not pdb_file:
                debug.error("The pdb file could not be downloaded. Try it with the PDB_FILE option.")
                return
        else:
            pdb_file = self._config.PDB_FILE
        off_sym = self._get_srvtrans_symbol(pdb_file, srv_module.DllBase) #retrouve address symbol de  = "SrvTransaction2DispatchTable
        if not off_sym:
            debug.error("SrvTransaction2DispatchTable symbol address not found")
            return
        rva_sym = off_sym + srv_module.DllBase #se met a l'adresse dans le module du depart de SrvTransaction2DispatchTable
        mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in win32.modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())
        #sav_rva=rva_sym
        #debug.info("RVA {0}".format(sav_rva))
        for i in range(17):
            if inc == 4:
                addr =     struct.unpack("<I", addr_space.zread(rva_sym, inc))[0]
            else:
                addr =     struct.unpack("<Q", addr_space.zread(rva_sym, inc))[0]
            #addr = rva_sym# trouve section .data  => moi je voudrais retrouver SrvTransaction2DispatchTable!!!!! => peut etre dans section data anormale!!!!! car SrvSmbOpen2 est dans PAGE
            module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(addr)) #recherche de le module en lien avec l'adresse de la page: 0xfffff880047e6060 srv.sys      PAGE 
            rva_sym += inc
            yield Address(addr), module

    def render_text(self, outfd, data):
        self.table_header(outfd, [('Ptr', '[addrpad]'),
                  ('Module', '12'),
                                  ('Section', '12'),
                                  ])
        for addr, module in data:
            if module:
                module_name = str(module.BaseDllName or '')
                sect_name = self._get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ''
            self.table_row(outfd,addr,module_name,sect_name)

    def unified_output(self, data):
        return TreeGrid([("Ptr", Address),
                       ("Module", str),
                       ("Section", str)],
                        self.generator(data))

    def generator(self, data):
        for addr, module in data:
            if module:
                module_name = str(module.BaseDllName or '')
                sect_name = self._get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ''
            yield (0, [Address(addr),str(module_name),str(sect_name)])


