# (c) 2009-2024 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Original PyFileServer (c) 2005 Ho Chun Wei.
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
Small wrapper for different etree packages.
"""

import logging
from io import StringIO

__docformat__ = "reStructuredText"

# _logger = util.get_module_logger(__name__)
_logger = logging.getLogger("wsgidav")

# Import XML support
use_lxml = False
try:
    from lxml import etree

    use_lxml = True
    _ElementType = etree._Element
except ImportError:
    # defusedxml doesn't define these non-parsing related objects
    from xml.etree.ElementTree import Element, SubElement, tostring

    from defusedxml import ElementTree as etree

    etree.Element = _ElementType = Element
    etree.SubElement = SubElement
    etree.tostring = tostring


# ========================================================================
# XML
# ========================================================================


def is_etree_element(obj):
    return isinstance(obj, _ElementType)


def string_to_xml(text):
    """Convert XML string into etree.Element."""
    try:
        return etree.XML(text)
    except Exception:
        # TODO:
        # ExpatError: reference to invalid character number: line 1, column 62
        # litmus fails, when xml is used instead of lxml
        # 18. propget............... FAIL (PROPFIND on `/temp/litmus/prop2':
        #   Could not read status line: connection was closed by server)
        # text = <ns0:high-unicode xmlns:ns0="http://example.com/neon/litmus/">&#55296;&#56320;
        #   </ns0:high-unicode>
        #        t2 = text.encode("utf8")
        #        return etree.XML(t2)
        _logger.error(
            "Error parsing XML string. "
            "If lxml is not available, and unicode is involved, then "
            "installing lxml _may_ solve this issue."
        )
        _logger.error(f"XML source: {text}")
        raise


def xml_to_bytes(element, *, pretty=False):
    """Wrapper for etree.tostring, that takes care of unsupported pretty_print
    option and prepends an encoding header."""
    if use_lxml:
        xml = etree.tostring(  # pylint: disable=unexpected-keyword-arg
            element,
            encoding="UTF-8",
            xml_declaration=True,
            pretty_print=pretty,
        )
    else:
        xml = etree.tostring(element, encoding="UTF-8")
        if not xml.startswith(b"<?xml "):
            xml = b'<?xml version="1.0" encoding="utf-8" ?>\n' + xml

    assert xml.startswith(b"<?xml ")  # ET should prepend an encoding header
    return xml


def make_multistatus_el():
    """Wrapper for etree.Element, that takes care of unsupported nsmap option."""
    if use_lxml:
        return etree.Element("{DAV:}multistatus", nsmap={"D": "DAV:"})
    return etree.Element("{DAV:}multistatus")


def make_prop_elem():
    """Wrapper for etree.Element, that takes care of unsupported nsmap option."""
    if use_lxml:
        return etree.Element("{DAV:}prop", nsmap={"D": "DAV:"})
    return etree.Element("{DAV:}prop")


def make_sub_element(parent, tag, *, nsmap=None):
    """Wrapper for etree.SubElement, that takes care of unsupported nsmap option."""
    if use_lxml:
        return etree.SubElement(parent, tag, nsmap=nsmap)
    return etree.SubElement(parent, tag)


def element_content_as_string(element):
    """Serialize etree.Element.

    Note: element may contain more than one child or only text (i.e. no child
          at all). Therefore the resulting string may raise an exception, when
          passed back to etree.XML().
    """
    if len(element) == 0:
        return element.text or ""  # Make sure, None is returned as ''
    stream = StringIO()
    for childnode in element:
        stream.write(xml_to_bytes(childnode, pretty=False) + "\n")
        # print(xml_to_bytes(childnode, pretty=False), file=stream)
    s = stream.getvalue()
    stream.close()
    return s
