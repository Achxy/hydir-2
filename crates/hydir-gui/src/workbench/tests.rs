use super::*;

fn fixture_app() -> AnalystApp {
    let bytes = include_bytes!("../../../../fuzz/corpus/elf_import/max2.elf");
    let mut app = AnalystApp::new(&egui::Context::default());
    app.spec = Some(import_elf(bytes).unwrap());
    app.function_index = Some(discover_functions(bytes).unwrap());
    app.shell.binary = Some(BinaryView::new(bytes.to_vec()));
    app.workbench_loaded = true;
    app.ensure_functions();
    app
}

#[test]
fn history_supports_back_forward_and_truncates_only_on_a_new_seek() {
    let mut nav = Navigation::default();
    for address in [0x1000, 0x2000, 0x3000] {
        nav.record(address);
    }
    assert_eq!(nav.step(false), Some(0x2000));
    nav.record(0x2000); // A frame observing a history navigation must preserve forward history.
    assert_eq!(nav.step(true), Some(0x3000));
    assert_eq!(nav.step(true), None);
    assert_eq!(nav.step(false), Some(0x2000));
    nav.record(0x4000);
    assert_eq!(nav.addresses, [0x1000, 0x2000, 0x4000]);
    assert_eq!(nav.step(true), None);
}

#[test]
fn byte_views_preserve_offsets_final_strings_and_scan_limits() {
    let view = BinaryView::new(b"\0abc\0hello world\0last".to_vec());
    assert_eq!(view.strings, [5..16, 17..21]);
    assert_eq!(&view.bytes[view.strings[1].clone()], b"last");
    assert!(!view.strings_truncated);
    let view = BinaryView::new(b"abcd\0".repeat(20_001));
    assert_eq!(view.strings.len(), 20_000);
    assert!(view.strings_truncated);
}

#[test]
fn hex_mapping_uses_file_extents_and_never_fabricates_bss_bytes() {
    let mut spec = fixture_app().spec.unwrap();
    let segment = &mut spec.mapped_segments[0];
    segment.virtual_address = Address(0x1000);
    segment.file_offset = Address(0x200);
    segment.file_size = 0x80;
    segment.memory_size = 0x100;
    spec.mapped_segments.truncate(1);
    spec.sections.clear();
    assert_eq!(virtual_to_offset(&spec, 0x1020), Some(0x220));
    assert_eq!(offset_to_virtual(&spec, 0x220), Some(0x1020));
    assert_eq!(virtual_to_offset(&spec, 0x1080), None);
    assert_eq!(virtual_to_offset(&spec, 0xfff), None);
    assert_eq!(offset_to_virtual(&spec, 0x280), None);
}

#[test]
fn function_seek_preserves_the_requested_view_across_worker_completion() {
    let mut app = fixture_app();
    // Intercept the operation without executing analysis in the test.
    let (tasks, received) = mpsc::sync_channel(4);
    app.tasks = tasks;
    app.open_tab(Tab::Graph);
    app.seek("hydir_max2").unwrap();
    assert!(matches!(received.recv().unwrap(), Task::Select(name) if name == "hydir_max2"));
    assert_eq!(app.tab, Tab::Graph);
    assert_eq!(app.selection_target_tab, Some(Tab::Graph));
    app.open_tab(Tab::Hexdump);
    assert_eq!(app.selection_target_tab, Some(Tab::Hexdump));
    assert_eq!(app.symbol.as_deref(), Some("hydir_max2"));
    app.busy = false;
    let address = app.selected_address;
    assert!(app.seek("0xffffffffffffffff").is_err());
    assert_eq!(app.selected_address, address);
}

#[test]
fn binary_switch_clears_navigation_and_bytes_but_preserves_layout() {
    let mut app = fixture_app();
    app.shell.layout.functions = Dock::Floating;
    app.shell.navigation.record(0x4000);
    app.shell.reset_binary();
    assert!(app.shell.binary.is_none());
    assert!(app.shell.functions.is_empty());
    assert!(app.shell.navigation.addresses.is_empty());
    assert!(app.shell.layout.functions == Dock::Floating);
}

#[test]
fn revision_changes_invalidate_cached_bytes_and_reject_late_byte_results() {
    let mut app = fixture_app();
    app.shell.binary_key = Some((app.spec.as_ref().unwrap().binary_sha256.clone(), false));
    app.current_local_path = Some(PathBuf::from("fixture.elf"));
    let old_digest = app.spec.as_ref().unwrap().binary_sha256.clone();
    app.spec.as_mut().unwrap().binary_sha256 = "a".repeat(64);
    let (tasks, received) = mpsc::sync_channel(4);
    app.tasks = tasks;
    app.sync_shell_binary();
    assert!(app.shell.binary.is_none());
    assert!(app.function_index.is_none());
    assert!(
        matches!(received.recv().unwrap(), Task::ReadBinaryView { binary_sha256 } if binary_sha256 == "a".repeat(64))
    );
    let (sender, events) = mpsc::sync_channel(2);
    app.events = events;
    sender
        .send(Event::BinaryViewLoaded {
            binary_sha256: old_digest,
            result: Ok(BinaryView::new(b"old bytes".to_vec())),
        })
        .unwrap();
    app.poll();
    assert!(app.shell.binary.is_none());
    sender
        .send(Event::BinaryViewLoaded {
            binary_sha256: "a".repeat(64),
            result: Ok(BinaryView::new(b"new bytes".to_vec())),
        })
        .unwrap();
    app.poll();
    assert_eq!(app.shell.binary.as_ref().unwrap().bytes, b"new bytes");
}

#[test]
fn console_aliases_navigate_real_views_and_reject_unrecognized_commands() {
    let mut app = fixture_app();
    app.run_workbench_command("px");
    assert_eq!(app.tab, Tab::Hexdump);
    app.run_workbench_command("agf");
    assert_eq!(app.tab, Tab::Graph);
    app.run_workbench_command("unsupported");
    assert!(
        app.shell
            .transcript
            .last()
            .unwrap()
            .contains("Unknown HydIR command")
    );
}

#[test]
fn saved_layout_roundtrips_closed_tabs_and_rejects_degenerate_values() {
    let mut layout = Layout {
        tabs: vec![Tab::Graph, Tab::Graph, Tab::Bytes],
        console_height: f32::NAN,
        ..Default::default()
    };
    layout.normalize();
    assert_eq!(layout.tabs, [Tab::Graph, Tab::Bytes]);
    assert_eq!(layout.console_height, 180.0);
    let bytes = serde_json::to_vec(&layout).unwrap();
    let restored: Layout = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.tabs, layout.tabs);
    assert!(restored.inspector == Dock::Hidden);
}

#[test]
fn ghidra_is_visible_by_default_and_reopens_after_a_saved_tab_was_closed() {
    assert!(Layout::default().tabs.contains(&Tab::GhidraPcode));
    assert!(Layout::default().tabs.contains(&Tab::Frida));
    let mut app = fixture_app();
    app.shell.layout.tabs = vec![Tab::Bytes];
    app.selection_target_tab = Some(Tab::Bytes);
    app.show_ghidra_pcode();
    assert_eq!(app.tab, Tab::GhidraPcode);
    assert_eq!(app.selection_target_tab, Some(Tab::GhidraPcode));
    assert!(app.shell.layout.tabs.contains(&Tab::GhidraPcode));
}

#[test]
fn pcode_listing_preserves_operation_identity_when_splitting_the_gutter() {
    assert_eq!(
        ghidra::listing_text(
            "    ram:0x20137f #1:1  unique:0x80 = INT_ADD(register:0x0, const:0x1) [exact Add]"
        ),
        (
            "#1:1",
            "unique:0x80 = INT_ADD(register:0x0, const:0x1) [exact Add]"
        )
    );
    assert_eq!(
        ghidra::listing_text("ram:0x20137c  4889e5               MOV"),
        ("", "4889e5               MOV")
    );
}

#[test]
fn all_focused_ghidra_and_frida_views_render_with_a_real_snapshot() {
    let bytes = include_bytes!("../../../../demo/hydir-prism.elf");
    let mut app = AnalystApp::new(&egui::Context::default());
    app.spec = Some(import_elf(bytes).unwrap());
    let snapshot: GhidraSnapshot = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/ghidra_prism_metadata_v2.json"
    ))
    .unwrap();
    let semantics = snapshot.pcode_function_ir().unwrap().lower_semantics();
    app.ghidra_pcode_lines = pcode_display_lines(&snapshot, Some(&semantics));
    app.ghidra_state_lines = pcode_state_lines(&semantics.lower_state());
    app.ghidra_semantics = Some(semantics);
    app.ghidra_snapshot = Some(snapshot);
    app.current_local_path = Some(PathBuf::from("demo/hydir-prism.elf"));
    app.workbench_loaded = true;
    for step in 0..GHIDRA_CAPTURE_NAMES.len() {
        app.prepare_ghidra_capture(step);
        egui::__run_test_ui(|ui| app.ghidra_workbench(ui));
    }
    app.open_tab(Tab::GhidraPcode);
    for mode in [
        ghidra::LlvmPane::Operations,
        ghidra::LlvmPane::Calls,
        ghidra::LlvmPane::Simplified,
    ] {
        app.shell.ghidra.pane = ghidra::GhidraPane::Llvm;
        app.shell.ghidra.llvm = mode;
        egui::__run_test_ui(|ui| app.ghidra_workbench(ui));
    }
    app.shell.ghidra.pane = ghidra::GhidraPane::Trace;
    app.shell.ghidra.trace = ghidra::TracePane::Assessment;
    egui::__run_test_ui(|ui| app.ghidra_workbench(ui));
}

#[test]
fn pcode_function_navigation_queues_a_matching_ghidra_export() {
    let bytes = include_bytes!("../../../../demo/hydir-prism.elf");
    let mut app = AnalystApp::new(&egui::Context::default());
    app.spec = Some(import_elf(bytes).unwrap());
    app.function_index = Some(discover_functions(bytes).unwrap());
    app.current_local_path = Some(PathBuf::from("demo/hydir-prism.elf"));
    app.ghidra_snapshot = Some(
        serde_json::from_slice(include_bytes!(
            "../../../../tests/fixtures/ghidra_prism_metadata_v2.json"
        ))
        .unwrap(),
    );
    app.ensure_functions();
    let index = app
        .shell
        .functions
        .iter()
        .position(|f| f.name == "hydir_stage_decision")
        .unwrap();
    let (tasks, received) = mpsc::sync_channel(4);
    app.tasks = tasks;
    app.open_function_row(index, Tab::GhidraPcode);
    assert!(
        matches!(received.recv().unwrap(), Task::Select(name) if name == "hydir_stage_decision")
    );
    assert!(
        matches!(received.recv().unwrap(), Task::AnalyzeGhidra { function: Some(entry), binary_sha256, .. }
        if entry == "0x20137c" && binary_sha256 == app.spec.as_ref().unwrap().binary_sha256)
    );
    assert_eq!(app.tab, Tab::GhidraPcode);
    assert!(app.ghidra_busy);
    app.busy = false;
    app.open_function_row(index, Tab::GhidraPcode);
    assert!(
        received.try_recv().is_err(),
        "Do not switch functions during a pending Ghidra export"
    );
}

#[test]
fn all_analysis_views_render_in_the_workbench_without_a_project() {
    let mut app = AnalystApp::new(&egui::Context::default());
    app.workbench_loaded = true;
    for tab in Tab::ALL {
        app.open_tab(tab);
        egui::__run_test_ui(|ui| app.workbench_ui(ui));
    }
}
