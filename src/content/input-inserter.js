/**
 * PromptGod — Input Inserter
 * Handles inserting masked text into both textarea/input and
 * contenteditable elements (ProseMirror, Quill, etc.).
 */

const PromptGodInserter = (() => {
  "use strict";

  /**
   * Walk up from the target to find the actual editable element.
   */
  function findEditableElement(el) {
    let current = el;
    while (current) {
      if (
        current.tagName === "TEXTAREA" ||
        current.tagName === "INPUT" ||
        current.contentEditable === "true" ||
        current.getAttribute?.("contenteditable") === "true"
      ) {
        return current;
      }
      current = current.parentElement;
    }
    return null;
  }

  /**
   * Insert text into a <textarea> or <input>.
   */
  function insertIntoTextarea(textarea, text) {
    const start = textarea.selectionStart || 0;
    const end = textarea.selectionEnd || 0;
    const before = textarea.value.substring(0, start);
    const after = textarea.value.substring(end);

    // Set value using native setter to trigger React/framework updates
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype,
      "value"
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(textarea, before + text + after);
    } else {
      textarea.value = before + text + after;
    }

    // Fire input event to notify frameworks
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    textarea.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /**
   * Insert text into a contenteditable div.
   * Uses a combination of approaches for maximum compatibility with
   * ProseMirror (ChatGPT, Claude) and Quill (Gemini).
   */
  function insertIntoContentEditable(el, text) {
    // Focus the element first
    el.focus();

    // Approach 1: Use the InputEvent API (best for modern editors)
    try {
      const inputEvent = new InputEvent("beforeinput", {
        inputType: "insertFromPaste",
        data: text,
        bubbles: true,
        cancelable: true,
        composed: true,
      });

      // Some editors need DataTransfer on the event
      if (typeof DataTransfer !== "undefined") {
        const dt = new DataTransfer();
        dt.setData("text/plain", text);
        Object.defineProperty(inputEvent, "dataTransfer", {
          value: dt,
        });
      }

      const wasHandled = !el.dispatchEvent(inputEvent);

      if (wasHandled) {
        el.dispatchEvent(
          new InputEvent("input", {
            inputType: "insertFromPaste",
            data: text,
            bubbles: true,
          })
        );
        return;
      }
    } catch (e) {
      // Fall through to next approach
    }

    // Approach 2: execCommand (deprecated but still widely effective)
    try {
      const success = document.execCommand("insertText", false, text);
      if (success) return;
    } catch (e) {
      // Fall through
    }

    // Approach 3: Direct DOM manipulation (last resort)
    const selection = window.getSelection();
    if (selection && selection.rangeCount > 0) {
      const range = selection.getRangeAt(0);
      range.deleteContents();
      const textNode = document.createTextNode(text);
      range.insertNode(textNode);
      // Move cursor to end of inserted text
      range.setStartAfter(textNode);
      range.setEndAfter(textNode);
      selection.removeAllRanges();
      selection.addRange(range);
    } else {
      // Absolute last resort: set textContent
      el.textContent = text;
    }

    // Fire input event
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }

  /**
   * Insert masked text into the target input element.
   * Works with both <textarea> and contenteditable divs.
   */
  function insertTextIntoInput(target, text) {
    const editableEl = findEditableElement(target);

    if (!editableEl) {
      // Last resort: try document.execCommand
      document.execCommand("insertText", false, text);
      return;
    }

    if (editableEl.tagName === "TEXTAREA" || editableEl.tagName === "INPUT") {
      insertIntoTextarea(editableEl, text);
    } else {
      insertIntoContentEditable(editableEl, text);
    }
  }

  return {
    insertTextIntoInput,
    insertIntoTextarea,
    insertIntoContentEditable,
    findEditableElement,
  };
})();
