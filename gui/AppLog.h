#pragma once

#include "imgui.h"

// Helper to wire demo markers located in code to a interactive browser
typedef void (*ImGuiDemoMarkerCallback)(const char* file, int line,
                                        const char* section, void* user_data);
extern ImGuiDemoMarkerCallback GImGuiDemoMarkerCallback;
extern void* GImGuiDemoMarkerCallbackUserData;

#define IMGUI_DEMO_MARKER(section)                                      \
	do {                                                                \
		if (GImGuiDemoMarkerCallback != NULL)                           \
			GImGuiDemoMarkerCallback(__FILE__, __LINE__, section,       \
			                         GImGuiDemoMarkerCallbackUserData); \
	} while (0)

struct AppLog {
	ImGuiTextBuffer Buf;
	ImGuiTextFilter Filter;
	ImVector<int> LineOffsets;
	bool AutoScroll;

	AppLog() {
		AutoScroll = true;
		Clear();
	}

	void Clear() {
		Buf.clear();
		LineOffsets.clear();
		LineOffsets.push_back(0);
	}

	void AddLog(const char* fmt, ...) IM_FMTARGS(2) {
		int old_size = Buf.size();
		va_list args;
		va_start(args, fmt);
		Buf.appendfv(fmt, args);
		va_end(args);
		for (int new_size = Buf.size(); old_size < new_size; old_size++) {
			if (Buf[old_size] == '\n') {
				LineOffsets.push_back(old_size + 1);
			}
		}
	}

	void Draw(const char* title, bool* p_open = nullptr) {
		if (!ImGui::Begin(title, p_open)) {
			ImGui::End();
		}

		// Options menu
		if (ImGui::BeginPopup("Options")) {
			ImGui::Checkbox("Auto-scroll", &AutoScroll);
			ImGui::EndPopup();
		}

		if (ImGui::Button("Options")) {
			ImGui::OpenPopup("Options");
		}
		ImGui::SameLine();
		bool clear = ImGui::Button("Clear");
		ImGui::SameLine();
		bool copy = ImGui::Button("Copy");
		ImGui::SameLine();
		Filter.Draw("Filter", -100.0f);

		ImGui::Separator();
		ImGui::BeginChild("scrolling", ImVec2(0, 0), false,
		                  ImGuiWindowFlags_HorizontalScrollbar);

		if (clear) {
			Clear();
		}
		if (copy) {
			ImGui::LogToClipboard();
		}

		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
		const char* buf = Buf.begin();
		const char* buf_end = Buf.end();
		if (Filter.IsActive()) {
			for (int line_no = 0; line_no < LineOffsets.Size; line_no++) {
				const char* line_start = buf + LineOffsets[line_no];
				const char* line_end =
				    (line_no + 1 < LineOffsets.Size)
				        ? (buf + LineOffsets[line_no + 1] - 1)
				        : buf_end;
				if (Filter.PassFilter(line_start, line_end))
					ImGui::TextUnformatted(line_start, line_end);
			}
		} else {
			ImGuiListClipper clipper;
			clipper.Begin(LineOffsets.Size);
			while (clipper.Step()) {
				for (int line_no = clipper.DisplayStart;
				     line_no < clipper.DisplayEnd; ++line_no) {
					const char* line_start = buf + LineOffsets[line_no];
					const char* line_end =
					    (line_no + 1 < LineOffsets.Size)
					        ? (buf + LineOffsets[line_no + 1] - 1)
					        : buf_end;
					ImGui::TextUnformatted(line_start, line_end);
				}
			}
			clipper.End();
		}
		ImGui::PopStyleVar();

		if (AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
			ImGui::SetScrollHereY(1.0f);
		}

		ImGui::EndChild();
		ImGui::End();
	}

	// Demonstrate creating a simple log window with basic filtering.
	static void ShowAppLog(bool* p_open) {
		static AppLog log;

		// For the demo: add a debug button _BEFORE_ the normal log window
		// contents We take advantage of a rarely used feature: multiple calls
		// to Begin()/End() are appending to the _same_ window. Most of the
		// contents of the window will be added by the log.Draw() call.
		ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);
		ImGui::Begin("Example: Log", p_open);
		IMGUI_DEMO_MARKER("Examples/Log");
		if (ImGui::SmallButton("[Debug] Add 5 entries")) {
			static int counter = 0;
			const char* categories[3] = {"info", "warn", "error"};
			const char* words[] = {
			    "Bumfuzzled",   "Cattywampus", "Snickersnee", "Abibliophobia",
			    "Absquatulate", "Nincompoop",  "Pauciloquent"};
			for (int n = 0; n < 5; n++) {
				const char* category =
				    categories[counter % IM_ARRAYSIZE(categories)];
				const char* word = words[counter % IM_ARRAYSIZE(words)];
				log.AddLog(
				    "[%05d] [%s] Hello, current time is %.1f, here's a word: "
				    "'%s'\n",
				    ImGui::GetFrameCount(), category, ImGui::GetTime(), word);
				counter++;
			}
		}
		ImGui::End();

		// Actually call in the regular Log helper (which will Begin() into the
		// same window as we just did)
		log.Draw("Example: Log", p_open);
	}
};