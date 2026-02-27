"""Characterisation tests for ContentSanitiser.

These tests capture the CURRENT behaviour of ContentSanitiser as a safety net
for later refactoring. If a test documents behaviour that seems like a bug,
it is still tested for the current output with a comment noting the concern.

Task: T004
"""

import base64

import pytest

from src.sanitizers.content_sanitizer import ContentSanitiser, SanitiseResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sanitiser() -> ContentSanitiser:
    return ContentSanitiser()


@pytest.fixture
def strict_sanitiser() -> ContentSanitiser:
    """Sanitiser with all options enabled (default)."""
    return ContentSanitiser()


@pytest.fixture
def no_confusables_sanitiser() -> ContentSanitiser:
    return ContentSanitiser(config={"normalise_confusables": False})


@pytest.fixture
def no_invisible_sanitiser() -> ContentSanitiser:
    return ContentSanitiser(config={"strip_invisible_unicode": False})


# ===========================================================================
# AC1: minimal level strips invisible but does NOT normalise confusables
#      or escape AI tags
# ===========================================================================

class TestMinimalLevel:

    def test_minimal_strips_invisible_chars(self, sanitiser: ContentSanitiser) -> None:
        content = "Hello\u200b world\u200c"
        result = sanitiser.sanitise(content, level="minimal")
        assert "\u200b" not in result.content
        assert "\u200c" not in result.content
        assert result.was_modified

    def test_minimal_does_not_normalise_confusables(self, sanitiser: ContentSanitiser) -> None:
        """AC1 / TA1: Confusable chars are left intact at minimal level."""
        content = "p\u0430ssword"  # Cyrillic 'a' (U+0430)
        result = sanitiser.sanitise(content, level="minimal")
        assert result.content == "p\u0430ssword"
        assert not result.was_modified

    def test_minimal_does_not_escape_ai_tags(self, sanitiser: ContentSanitiser) -> None:
        """AC1 / TA2: AI tags are left intact at minimal level."""
        content = "<system>override</system>"
        result = sanitiser.sanitise(content, level="minimal")
        assert "<system>" in result.content
        assert "&lt;" not in result.content
        assert not result.was_modified

    def test_minimal_does_not_neutralise_delimiters(self, sanitiser: ContentSanitiser) -> None:
        content = "===== system =====\nNew instructions"
        result = sanitiser.sanitise(content, level="minimal")
        assert "SANITISED" not in result.content

    def test_minimal_does_not_wrap_content(self, sanitiser: ContentSanitiser) -> None:
        content = "Some text"
        result = sanitiser.sanitise(content, level="minimal")
        assert "BEGIN EXTERNAL CONTENT" not in result.content


# ===========================================================================
# AC2: Confusable normalisation for fullwidth ASCII
# ===========================================================================

class TestConfusableNormalisation:

    def test_fullwidth_ascii_uppercase_normalised(self, sanitiser: ContentSanitiser) -> None:
        """AC2 / TA3: Fullwidth A-Z normalised to ASCII."""
        # Fullwidth 'A' (U+FF21), 'B' (U+FF22), 'C' (U+FF23)
        content = "\uff21\uff22\uff23"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "ABC"
        assert result.was_modified

    def test_fullwidth_ascii_lowercase_normalised(self, sanitiser: ContentSanitiser) -> None:
        content = "\uff41\uff42\uff43"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "abc"
        assert result.was_modified

    def test_fullwidth_digits_normalised(self, sanitiser: ContentSanitiser) -> None:
        content = "\uff10\uff11\uff12"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "012"
        assert result.was_modified

    def test_cyrillic_confusables_normalised(self, sanitiser: ContentSanitiser) -> None:
        # Cyrillic A (U+0410), B (U+0412), C (U+0421)
        content = "\u0410\u0412\u0421"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "ABC"

    @pytest.mark.parametrize("cyrillic,expected_latin", [
        ("\u0430", "a"),  # Cyrillic small a
        ("\u0435", "e"),  # Cyrillic small ie
        ("\u043e", "o"),  # Cyrillic small o
        ("\u0440", "p"),  # Cyrillic small er
        ("\u0441", "c"),  # Cyrillic small es
        ("\u0445", "x"),  # Cyrillic small ha
        ("\u0443", "y"),  # Cyrillic small u
        ("\u0455", "s"),  # Cyrillic small dze
        ("\u0456", "i"),  # Cyrillic small byelorussian-ukrainian i
        ("\u0458", "j"),  # Cyrillic small je
        ("\u04bb", "h"),  # Cyrillic small shha
    ])
    def test_cyrillic_lowercase_confusables(
        self, sanitiser: ContentSanitiser, cyrillic: str, expected_latin: str
    ) -> None:
        result = sanitiser.sanitise(cyrillic, level="standard")
        assert result.content == expected_latin


# ===========================================================================
# AC3: Multiple sanitisation passes compose correctly
# ===========================================================================

class TestMultiplePassComposition:

    def test_combined_invisible_and_ai_tags(self, sanitiser: ContentSanitiser) -> None:
        """AC3 / TA4: Both invisible char stripping and AI tag escaping fire."""
        content = "Hello\u200b <system>override</system>"
        result = sanitiser.sanitise(content, level="standard")
        assert "\u200b" not in result.content
        assert "<system>" not in result.content
        assert "&lt;system&gt;" in result.content
        assert result.was_modified
        assert len(result.changes) == 2
        assert "Stripped 1 invisible Unicode characters" in result.changes
        assert "Escaped 2 AI-targeted tags" in result.changes

    def test_combined_confusables_and_invisible(self, sanitiser: ContentSanitiser) -> None:
        content = "p\u0430\u200bssword"  # Cyrillic a + zero-width space
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "password"
        assert result.was_modified
        assert len(result.changes) == 2

    def test_combined_all_passes_strict(self, sanitiser: ContentSanitiser) -> None:
        """At strict level, all passes should fire on content with all threat types."""
        content = "p\u0430ss\u200b <system>x</system> ===== system ====="
        result = sanitiser.sanitise(content, level="strict")
        # Invisible stripped
        assert "\u200b" not in result.content
        # Confusables normalised
        assert "\u0430" not in result.content
        # AI tags escaped
        assert "&lt;system&gt;" in result.content
        # Delimiters neutralised
        assert "SANITISED" in result.content
        # Content wrapped
        assert "BEGIN EXTERNAL CONTENT" in result.content
        assert result.was_modified


# ===========================================================================
# AC4: Empty string input
# ===========================================================================

class TestEmptyInput:

    def test_empty_content_unchanged(self, sanitiser: ContentSanitiser) -> None:
        """AC4 / TA5: Empty string returns unchanged with was_modified=false."""
        result = sanitiser.sanitise("", level="standard")
        assert result.content == ""
        assert not result.was_modified
        assert result.changes == []
        assert result.original_length == 0
        assert result.sanitised_length == 0

    def test_empty_content_minimal(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("", level="minimal")
        assert result.content == ""
        assert not result.was_modified

    def test_empty_content_strict(self, sanitiser: ContentSanitiser) -> None:
        """Strict level wraps even empty content."""
        result = sanitiser.sanitise("", level="strict")
        assert "BEGIN EXTERNAL CONTENT" in result.content
        assert result.was_modified


# ===========================================================================
# AC5: SanitiseResult.to_dict()
# ===========================================================================

class TestSanitiseResultToDict:

    def test_to_dict_structure(self, sanitiser: ContentSanitiser) -> None:
        """AC5 / TA6: to_dict returns correct structure."""
        result = sanitiser.sanitise("test", level="standard")
        d = result.to_dict()
        assert set(d.keys()) == {
            "content", "changes", "original_length", "sanitised_length", "was_modified"
        }

    def test_to_dict_values_clean(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("clean text", level="standard")
        d = result.to_dict()
        assert d["content"] == "clean text"
        assert d["changes"] == []
        assert d["original_length"] == 10
        assert d["sanitised_length"] == 10
        assert d["was_modified"] is False

    def test_to_dict_values_modified(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("Hello\u200b", level="standard")
        d = result.to_dict()
        assert d["content"] == "Hello"
        assert len(d["changes"]) > 0
        assert d["original_length"] == 6  # 5 visible + 1 invisible
        assert d["sanitised_length"] == 5
        assert d["was_modified"] is True


# ===========================================================================
# Sanitise levels: each level tested
# ===========================================================================

class TestSanitiseLevels:

    @pytest.mark.parametrize("level", ["minimal", "standard", "strict"])
    def test_clean_content_at_each_level(self, sanitiser: ContentSanitiser, level: str) -> None:
        """Clean content should pass through unchanged (except strict wrapping)."""
        content = "This is perfectly normal English text."
        result = sanitiser.sanitise(content, level=level)
        if level == "strict":
            assert "BEGIN EXTERNAL CONTENT" in result.content
            assert content in result.content
            assert result.was_modified  # wrapping counts as modification
        else:
            assert result.content == content
            assert not result.was_modified

    def test_level_escalation_changes(self, sanitiser: ContentSanitiser) -> None:
        """Higher levels should produce more changes on mixed-threat content."""
        content = "Hello\u200b <system>test</system>"
        minimal = sanitiser.sanitise(content, level="minimal")
        standard = sanitiser.sanitise(content, level="standard")
        strict = sanitiser.sanitise(content, level="strict")
        assert len(minimal.changes) < len(standard.changes)
        assert len(standard.changes) < len(strict.changes)


# ===========================================================================
# Unicode edge cases
# ===========================================================================

class TestUnicodeEdgeCases:

    def test_zero_width_chars_stripped(self, sanitiser: ContentSanitiser) -> None:
        """Zero-width space, joiner, non-joiner all stripped."""
        content = "\u200b\u200c\u200d"
        result = sanitiser.sanitise(content, level="minimal")
        assert result.content == ""
        assert result.was_modified

    def test_word_joiner_stripped(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("A\u2060B", level="minimal")
        assert result.content == "AB"

    def test_bom_stripped(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("\ufeffHello", level="minimal")
        assert result.content == "Hello"
        assert result.was_modified

    def test_soft_hyphen_stripped(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("pass\u00adword", level="minimal")
        assert result.content == "password"
        assert result.was_modified

    def test_rtl_override_stripped(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("hello\u202eworld", level="minimal")
        assert result.content == "helloworld"
        assert result.was_modified

    def test_directional_isolates_stripped(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("A\u2066B\u2069C", level="minimal")
        assert result.content == "ABC"
        assert result.was_modified

    @pytest.mark.parametrize("char,name", [
        ("\u200b", "zero-width space"),
        ("\u200c", "zero-width non-joiner"),
        ("\u200d", "zero-width joiner"),
        ("\u2060", "word joiner"),
        ("\u180e", "mongolian vowel separator"),
        ("\ufeff", "BOM / zero-width no-break space"),
        ("\u00ad", "soft hyphen"),
        ("\u034f", "combining grapheme joiner"),
        ("\u061c", "arabic letter mark"),
        ("\u2061", "function application"),
        ("\u2062", "invisible times"),
        ("\u2063", "invisible separator"),
        ("\u2064", "invisible plus"),
        ("\u2066", "left-to-right isolate"),
        ("\u2067", "right-to-left isolate"),
        ("\u2068", "first strong isolate"),
        ("\u2069", "pop directional isolate"),
        ("\u202a", "left-to-right embedding"),
        ("\u202b", "right-to-left embedding"),
        ("\u202c", "pop directional formatting"),
        ("\u202d", "left-to-right override"),
        ("\u202e", "right-to-left override"),
    ])
    def test_individual_invisible_char_stripped(
        self, sanitiser: ContentSanitiser, char: str, name: str
    ) -> None:
        """Each invisible character in the set should be stripped."""
        content = f"A{char}B"
        result = sanitiser.sanitise(content, level="minimal")
        assert result.content == "AB", f"Failed to strip {name} (U+{ord(char):04X})"
        assert result.was_modified


# ===========================================================================
# Very long input
# ===========================================================================

class TestLongInput:

    def test_very_long_clean_input(self, sanitiser: ContentSanitiser) -> None:
        """Long clean input should pass through unchanged."""
        content = "A" * 100_000
        result = sanitiser.sanitise(content, level="standard")
        assert len(result.content) == 100_000
        assert not result.was_modified

    def test_long_input_with_invisible_chars(self, sanitiser: ContentSanitiser) -> None:
        content = ("A\u200b" * 50_000)
        result = sanitiser.sanitise(content, level="minimal")
        assert len(result.content) == 50_000
        assert result.was_modified

    def test_long_input_original_length_recorded(self, sanitiser: ContentSanitiser) -> None:
        content = "B" * 100_000
        result = sanitiser.sanitise(content, level="standard")
        assert result.original_length == 100_000
        assert result.sanitised_length == 100_000


# ===========================================================================
# Nested encoding
# ===========================================================================

class TestNestedEncoding:

    def test_base64_encoded_attack_not_decoded(self, sanitiser: ContentSanitiser) -> None:
        """NOTE: The sanitiser does NOT decode base64. An encoded attack passes through.
        This may be a gap but it is the current behaviour."""
        encoded = base64.b64encode(b"<system>attack</system>").decode()
        content = f"data: {encoded}"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == content
        assert not result.was_modified

    def test_url_encoded_attack_not_decoded(self, sanitiser: ContentSanitiser) -> None:
        """NOTE: The sanitiser does NOT decode URL encoding. An encoded attack passes through.
        This may be a gap but it is the current behaviour."""
        content = "test%3Csystem%3Eattack"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == content
        assert not result.was_modified

    def test_html_entity_encoded_not_double_escaped(self, sanitiser: ContentSanitiser) -> None:
        """Already-escaped content should not be double-escaped if not matching AI tag pattern."""
        content = "test &lt;div&gt; content"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == content
        assert not result.was_modified


# ===========================================================================
# Code block preservation
# ===========================================================================

class TestCodeBlockPreservation:

    def test_fenced_code_block_preserved(self, sanitiser: ContentSanitiser) -> None:
        content = "Normal text\n```\n<system>code here</system>\n```\nMore text"
        result = sanitiser.sanitise(content, level="standard")
        assert "<system>code here</system>" in result.content

    def test_inline_code_preserved(self, sanitiser: ContentSanitiser) -> None:
        content = "use `<system>` tag"
        result = sanitiser.sanitise(content, level="standard")
        assert "`<system>`" in result.content

    def test_code_block_ai_tags_outside_escaped(self, sanitiser: ContentSanitiser) -> None:
        """Tags outside code blocks should still be escaped."""
        content = "before\n```\n<system>inner</system>\n```\nafter <system>outer</system>"
        result = sanitiser.sanitise(content, level="standard")
        assert "<system>inner</system>" in result.content
        assert "&lt;system&gt;outer&lt;/system&gt;" in result.content

    def test_confusables_outside_code_block_normalised(self, sanitiser: ContentSanitiser) -> None:
        content = "p\u0430ss ```code``` w\u043erd"
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == "pass ```code``` word"

    def test_nested_code_blocks(self, sanitiser: ContentSanitiser) -> None:
        """Multiple code blocks in same content."""
        content = "```\nblock1\n```\ntext\n```\nblock2\n```"
        result = sanitiser.sanitise(content, level="standard")
        assert "block1" in result.content
        assert "block2" in result.content

    def test_code_block_preservation_disabled(self) -> None:
        """When preserve_code_blocks is off, code blocks are sanitised too."""
        s = ContentSanitiser(config={"preserve_code_blocks": False})
        content = "```\n<system>code</system>\n```"
        result = s.sanitise(content, level="standard")
        # AI tags inside code block should now be escaped
        assert "&lt;system&gt;" in result.content


# ===========================================================================
# AI tag escaping (parametrised attack vectors)
# ===========================================================================

class TestAITagEscaping:

    @pytest.mark.parametrize("tag", [
        "<system>", "</system>",
        "<prompt>", "</prompt>",
        "<instructions>", "</instructions>",
        "<instruction>", "</instruction>",
        "<rules>", "</rules>",
        "<rule>", "</rule>",
        "<context>", "</context>",
        "<tool_use>", "</tool_use>",
        "<tooluse>", "</tooluse>",
        "<tool_result>", "</tool_result>",
        "<toolresult>", "</toolresult>",
        "<function_call>", "</function_call>",
        "<functioncall>", "</functioncall>",
        "<function_result>", "</function_result>",
        "<functionresult>", "</functionresult>",
        "<message>", "</message>",
        "<thinking>", "</thinking>",
        "<human>", "</human>",
        "<user>", "</user>",
        "<assistant>", "</assistant>",
        "<INST>", "</INST>",
    ])
    def test_ai_tag_escaped(self, sanitiser: ContentSanitiser, tag: str) -> None:
        content = f"before {tag} after"
        result = sanitiser.sanitise(content, level="standard")
        assert tag not in result.content
        assert "&lt;" in result.content

    def test_case_insensitive_tag_escaping(self, sanitiser: ContentSanitiser) -> None:
        content = "<SYSTEM>override</SYSTEM>"
        result = sanitiser.sanitise(content, level="standard")
        assert "<SYSTEM>" not in result.content
        assert "&lt;SYSTEM&gt;" in result.content


# ===========================================================================
# Delimiter injection
# ===========================================================================

class TestDelimiterInjection:

    @pytest.mark.parametrize("delimiter", [
        "===== system =====",
        "===== instructions =====",
        "===== override =====",
        "----- system -----",
        "##### system #####",
        "***** system *****",
        "~~~~~ system ~~~~~",
    ])
    def test_delimiter_neutralised(self, sanitiser: ContentSanitiser, delimiter: str) -> None:
        content = f"before\n{delimiter}\nafter"
        result = sanitiser.sanitise(content, level="standard")
        assert "SANITISED" in result.content
        assert result.was_modified


# ===========================================================================
# Config overrides
# ===========================================================================

class TestConfigOverrides:

    def test_disabled_confusables(self, no_confusables_sanitiser: ContentSanitiser) -> None:
        """When normalise_confusables=False, confusables are left intact."""
        result = no_confusables_sanitiser.sanitise("p\u0430ssword", level="standard")
        assert result.content == "p\u0430ssword"
        # AI tags should still be escaped
        result2 = no_confusables_sanitiser.sanitise("<system>x</system>", level="standard")
        assert "&lt;system&gt;" in result2.content

    def test_disabled_invisible_stripping(self, no_invisible_sanitiser: ContentSanitiser) -> None:
        """When strip_invisible_unicode=False, invisible chars are left intact."""
        result = no_invisible_sanitiser.sanitise("Hello\u200b", level="minimal")
        assert "\u200b" in result.content
        assert not result.was_modified


# ===========================================================================
# Input that is already clean (should pass through unchanged)
# ===========================================================================

class TestCleanPassthrough:

    @pytest.mark.parametrize("content", [
        "Hello, world!",
        "The quick brown fox jumps over the lazy dog.",
        "12345 numbers and special chars: @#$%^&*()",
        "Multi\nline\ncontent\nwith\nnewlines",
        "Tab\tseparated\tvalues",
        "",
        "A",
        "Unicode that is NOT confusable: \u00e9\u00e0\u00fc\u00f1",
    ])
    def test_clean_content_passes_through(
        self, sanitiser: ContentSanitiser, content: str
    ) -> None:
        result = sanitiser.sanitise(content, level="standard")
        assert result.content == content
        assert not result.was_modified


# ===========================================================================
# Mixed threat types
# ===========================================================================

class TestMixedThreats:

    def test_invisible_plus_confusable_plus_tag(self, sanitiser: ContentSanitiser) -> None:
        content = "\u200bp\u0430ss <system>go</system>"
        result = sanitiser.sanitise(content, level="standard")
        assert "\u200b" not in result.content
        assert "\u0430" not in result.content
        assert "&lt;system&gt;" in result.content
        assert len(result.changes) == 3

    def test_delimiter_plus_tag(self, sanitiser: ContentSanitiser) -> None:
        content = "===== system =====\n<prompt>attack</prompt>"
        result = sanitiser.sanitise(content, level="standard")
        assert "SANITISED" in result.content
        assert "&lt;prompt&gt;" in result.content

    def test_all_threat_types_strict(self, sanitiser: ContentSanitiser) -> None:
        content = "\u200b\u0430 <system>x</system> ===== override ====="
        result = sanitiser.sanitise(content, level="strict")
        assert result.was_modified
        # Should have 5 changes: invisible, confusable, AI tag, delimiter, wrapping
        assert len(result.changes) == 5
        assert "BEGIN EXTERNAL CONTENT" in result.content


# ===========================================================================
# SanitiseResult properties
# ===========================================================================

class TestSanitiseResultObject:

    def test_was_modified_false_for_clean(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("clean", level="standard")
        assert not result.was_modified

    def test_was_modified_true_when_changed(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("Hello\u200b", level="standard")
        assert result.was_modified

    def test_original_and_sanitised_lengths(self, sanitiser: ContentSanitiser) -> None:
        content = "AB\u200bCD"
        result = sanitiser.sanitise(content, level="standard")
        assert result.original_length == 5
        assert result.sanitised_length == 4

    def test_changes_list_types(self, sanitiser: ContentSanitiser) -> None:
        result = sanitiser.sanitise("Hello\u200b <system>x</system>", level="standard")
        assert isinstance(result.changes, list)
        assert all(isinstance(c, str) for c in result.changes)
