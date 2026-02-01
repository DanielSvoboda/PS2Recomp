#include "ps2recomp/elf_parser.h"
#include <iostream>
#include <stdexcept>

namespace ps2recomp
{

    ElfParser::ElfParser(const std::string &filePath)
        : m_filePath(filePath), m_elf(new ELFIO::elfio())
    {
    }

    bool ElfParser::isExecutableSection(const ELFIO::section *section) const
    {
        return (section->get_flags() & ELFIO::SHF_EXECINSTR) != 0;
    }

    bool ElfParser::isDataSection(const ELFIO::section *section) const
    {
        return (section->get_flags() & ELFIO::SHF_ALLOC) != 0 &&
               !(section->get_flags() & ELFIO::SHF_EXECINSTR);
    }

    std::vector<Function> ElfParser::extractFunctions()
    {
        std::vector<Function> functions;

        for (const auto &symbol : m_symbols)
        {
            if (symbol.isFunction && symbol.size > 0)
            {
                Function func;
                func.name = symbol.name;
                func.start = symbol.address;
                func.end = symbol.address + symbol.size;
                func.isRecompiled = false;
                func.isStub = false;

                functions.push_back(func);
            }
        }

        std::sort(functions.begin(), functions.end(),
                  [](const Function &a, const Function &b)
                  { return a.start < b.start; });

        return functions;
    }

    std::vector<Symbol> ElfParser::extractSymbols()
    {
        return m_symbols;
    }

    std::vector<Section> ElfParser::getSections()
    {
        return m_sections;
    }

    std::vector<Relocation> ElfParser::getRelocations()
    {
        return m_relocations;
    }

    std::vector<Variable> ElfParser::getVariables()
    {
        return m_variables;
    }

    bool ElfParser::isValidAddress(uint32_t address) const
    {
        for (const auto &section : m_sections)
        {
            if (address >= section.address && address < (section.address + section.size))
            {
                return true;
            }
        }

        return false;
    }

    uint32_t ElfParser::readWord(uint32_t address) const
    {
        for (const auto &section : m_sections)
        {
            if (address >= section.address && address < (section.address + section.size))
            {
                if (section.data)
                {
                    uint32_t offset = address - section.address;
                    return *reinterpret_cast<uint32_t *>(section.data + offset);
                }
            }
        }

        throw std::runtime_error("Invalid address for readWord: " + std::to_string(address));
    }

    uint8_t *ElfParser::getSectionData(const std::string &sectionName)
    {
        for (const auto &section : m_sections)
        {
            if (section.name == sectionName)
            {
                return section.data;
            }
        }

        return nullptr;
    }

    uint32_t ElfParser::getSectionAddress(const std::string &sectionName)
    {
        for (const auto &section : m_sections)
        {
            if (section.name == sectionName)
            {
                return section.address;
            }
        }

        return 0;
    }

    uint32_t ElfParser::getSectionSize(const std::string &sectionName)
    {
        for (const auto &section : m_sections)
        {
            if (section.name == sectionName)
            {
                return section.size;
            }
        }

        return 0;
    }

    uint32_t ElfParser::getEntryPoint() const
    {
        return static_cast<uint32_t>(m_elf->get_entry());
    }

    ElfParser::~ElfParser() = default;

    bool ElfParser::parse()
    {
        if (!m_elf->load(m_filePath))
        {
            std::cerr << "Error: Could not load ELF file: " << m_filePath << std::endl;
            return false;
        }

        // Check if this is a PS2 ELF (MIPS R5900)
        if (m_elf->get_machine() != ELFIO::EM_MIPS)
        {
            std::cerr << "Error: Not a MIPS ELF file" << std::endl;
            return false;
        }

        loadSections();
        loadSymbols();
        loadRelocations();
        extractVariables();

        return true;
    }

    void ElfParser::loadSections()
    {
        m_sections.clear();

        ELFIO::Elf_Half sec_num = m_elf->sections.size();

        for (ELFIO::Elf_Half i = 0; i < sec_num; ++i)
        {
            ELFIO::section *psec = m_elf->sections[i];

            Section section;
            section.name = psec->get_name();
            section.address = psec->get_address();
            section.size = psec->get_size();
            section.offset = psec->get_offset();
            section.isCode = isExecutableSection(psec);
            section.isData = isDataSection(psec);
            section.isBSS = (psec->get_type() == ELFIO::SHT_NOBITS);
            section.isReadOnly = !(psec->get_flags() & ELFIO::SHF_WRITE);

            if (psec->get_size() > 0 && psec->get_type() != ELFIO::SHT_NOBITS)
            {
                section.data = (uint8_t *)psec->get_data();
            }
            else
            {
                section.data = nullptr;
            }

            m_sections.push_back(section);
        }
    }

    void ElfParser::loadSymbols()
    {
        m_symbols.clear();

        for (ELFIO::Elf_Half i = 0; i < m_elf->sections.size(); ++i)
        {
            ELFIO::section *psec = m_elf->sections[i];

            if (psec->get_type() == ELFIO::SHT_SYMTAB || psec->get_type() == ELFIO::SHT_DYNSYM)
            {
                ELFIO::symbol_section_accessor symbols(*m_elf, psec);

                ELFIO::Elf_Xword sym_num = symbols.get_symbols_num();

                ELFIO::section *pstrSec = m_elf->sections[psec->get_link()];
                ELFIO::string_section_accessor strings(pstrSec);

                for (ELFIO::Elf_Xword j = 0; j < sym_num; ++j)
                {
                    std::string name;
                    ELFIO::Elf64_Addr value;
                    ELFIO::Elf_Xword size;
                    unsigned char bind;
                    unsigned char type;
                    ELFIO::Elf_Half section_index;
                    unsigned char other;

                    symbols.get_symbol(j, name, value, size, bind, type, section_index, other);

                    // Skip empty symbols or those with invalid section index
                    if (name.empty() || section_index == ELFIO::SHN_UNDEF)
                    {
                        continue;
                    }

                    Symbol symbol;
                    symbol.name = name;
                    symbol.address = static_cast<uint32_t>(value);
                    symbol.size = static_cast<uint32_t>(size);
                    symbol.isFunction = (type == ELFIO::STT_FUNC);
                    symbol.isImported = (bind == ELFIO::STB_GLOBAL && section_index == ELFIO::SHN_UNDEF);
                    symbol.isExported = (bind == ELFIO::STB_GLOBAL && section_index != ELFIO::SHN_UNDEF);
                    symbol.isObject = (type == ELFIO::STT_OBJECT);

                    m_symbols.push_back(symbol);
                }
            }
        }
    }

    void ElfParser::loadRelocations()
    {
        m_relocations.clear();

        for (ELFIO::Elf_Half i = 0; i < m_elf->sections.size(); ++i)
        {
            ELFIO::section *psec = m_elf->sections[i];

            if (psec->get_type() != ELFIO::SHT_REL &&
                psec->get_type() != ELFIO::SHT_RELA)
                continue;

            ELFIO::relocation_section_accessor relocs(*m_elf, psec);

            // target section where relocation is applied
            ELFIO::section* targetSec = m_elf->sections[psec->get_info()];
            uint32_t targetBase = static_cast<uint32_t>(targetSec->get_address());

            for (ELFIO::Elf_Xword j = 0; j < relocs.get_entries_num(); ++j)
            {
                ELFIO::Elf64_Addr offset;
                ELFIO::Elf_Word symbol;
                ELFIO::Elf_Word type;
                ELFIO::Elf_Sxword addend = 0;

   
                    relocs.get_entry(j, offset, symbol, type, addend);

                Relocation r;
                r.offset = targetBase + static_cast<uint32_t>(offset);
                r.symbol = symbol;
                r.type = type;
                r.addend = static_cast<int32_t>(addend);

                m_relocations.push_back(r);
            }
        }
    }


    void ElfParser::extractVariables()
    {
        m_variables.clear();

        for (size_t i = 0; i < m_symbols.size(); ++i)
        {
            const auto& sym = m_symbols[i];

            if (!sym.isObject)
                continue;

            if (sym.address == 0)
                continue;

            Variable v;
            v.name = sym.name;
            v.address = sym.address;
            v.size = sym.size;
            v.isObject = true;
            v.sectionName = "";
            v.isBSS = false;
            v.isReadOnly = false;

            // encontrar seção da variável
            const Section* secPtr = nullptr;
            for (const auto& sec : m_sections)
            {
                if (sym.address >= sec.address &&
                    sym.address < sec.address + sec.size)
                {
                    secPtr = &sec;
                    break;
                }
            }

            if (secPtr)
            {
                v.sectionName = secPtr->name;
                v.isBSS = secPtr->isBSS;
                v.isReadOnly = secPtr->isReadOnly;

                if (!v.isBSS && secPtr->data && v.size > 0)
                {
                    uint32_t offset = sym.address - secPtr->address;
                    v.initData.resize(v.size);
                    std::memcpy(v.initData.data(),
                        secPtr->data + offset,
                        v.size);
                }
            }
            else
            {
                v.isBSS = true;
            }

            // associate relocations with the variable
            for (const auto& rel : m_relocations)
            {
                if (rel.offset >= v.address &&
                    rel.offset < v.address + (v.size ? v.size : 1))
                {
                    Variable::RelocRef rr;
                    rr.offsetIntoVar = rel.offset - v.address;
                    rr.type = rel.type;
                    rr.symbolIndex = rel.symbol;
                    rr.addend = rel.addend;
                    v.relocRefs.push_back(rr);
                }
            }

            m_variables.push_back(std::move(v));
        }
    }


}