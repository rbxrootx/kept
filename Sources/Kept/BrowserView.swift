import KDBXKit
import SwiftUI

struct BrowserView: View {
    @Environment(AppModel.self) private var model
    @State private var columnVisibility = NavigationSplitViewVisibility.all

    var body: some View {
        @Bindable var model = model
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 320)
        } content: {
            EntryListView()
                .navigationSplitViewColumnWidth(min: 240, ideal: 300, max: 480)
        } detail: {
            if let entry = model.selectedEntry {
                EntryDetailView(entry: entry)
                    .id(entry.id)
            } else {
                ContentUnavailableView("No Item Selected", systemImage: "key.horizontal",
                                       description: Text("Select an item to see its details."))
            }
        }
        .searchable(text: $model.searchText, isPresented: $model.focusSearch, placement: .sidebar,
                    prompt: "Search")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button { model.lock() } label: { Label("Lock", systemImage: "lock") }
                    .help("Lock database (⌘L)")
            }
        }
        .onChange(of: model.sidebarSelection) {
            if let id = model.selectedEntryID, !model.visibleEntries.contains(where: { $0.id == id }) {
                model.selectedEntryID = nil
            }
        }
    }
}

// MARK: - Sidebar

struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @AppStorage(Prefs.showRecycleBin) private var showRecycleBin = false

    var body: some View {
        @Bindable var model = model
        let db = model.database
        let entries = db?.activeEntries ?? []

        List(selection: $model.sidebarSelection) {
            Section(db?.name ?? "") {
                SidebarRow(title: "All Items", icon: "key.horizontal", tint: .accentColor, count: entries.count)
                    .tag(SidebarItem.all)
                SidebarRow(title: "Favorites", icon: "star.fill", tint: .yellow, count: model.favoriteEntries.count)
                    .tag(SidebarItem.favorites)
                let codes = entries.filter { $0.totp != nil }.count
                if codes > 0 {
                    SidebarRow(title: "Verification Codes", icon: "clock.badge.checkmark", tint: .green, count: codes)
                        .tag(SidebarItem.codes)
                }
            }

            let groups = visibleGroups(db?.root.groups ?? [])
            if !groups.isEmpty {
                Section("Groups") {
                    OutlineGroup(groups, children: \.children) { group in
                        Label(group.name.isEmpty ? "Untitled Group" : group.name, systemImage: group.id == db?.recycleBinID ? "trash" : groupSymbol(group.iconID))
                            .badge(group.allEntries.count)
                            .tag(SidebarItem.group(group.id))
                    }
                }
            }

            let tags = db?.allTags ?? []
            if !tags.isEmpty {
                Section("Tags") {
                    ForEach(tags, id: \.self) { tag in
                        Label(tag, systemImage: "tag").tag(SidebarItem.tag(tag))
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func visibleGroups(_ groups: [KDBXGroup]) -> [KDBXGroup] {
        groups.compactMap { group in
            if group.id == model.database?.recycleBinID && !showRecycleBin { return nil }
            var copy = group
            copy.groups = visibleGroups(group.groups)
            return copy
        }
    }

    private func groupSymbol(_ iconID: Int) -> String {
        switch iconID {
        case 1, 8, 16, 35: "globe"
        case 3, 27, 38: "server.rack"
        case 9, 58: "person.text.rectangle"
        case 19, 25, 40: "envelope"
        case 20, 34: "gearshape"
        case 37, 66: "banknote"
        case 60: "house"
        case 61: "star"
        case 64: "apple.logo"
        case 18, 23: "display"
        case 29, 30: "terminal"
        case 43: "trash"
        default: "folder"
        }
    }
}

private struct SidebarRow: View {
    let title: String
    let icon: String
    let tint: Color
    let count: Int

    var body: some View {
        Label { Text(title) } icon: { Image(systemName: icon).foregroundStyle(tint) }
            .badge(count)
    }
}

// MARK: - Entry list

struct EntryListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        let entries = model.visibleEntries

        List(entries, selection: $model.selectedEntryID) { entry in
            EntryRow(entry: entry, isFavorite: model.isFavorite(entry))
                .tag(entry.id)
        }
        .contextMenu(forSelectionType: UUID.self) { ids in
            if let id = ids.first, let entry = entries.first(where: { $0.id == id }) {
                EntryActions(entry: entry)
            }
        } primaryAction: { ids in
            if let id = ids.first, let entry = entries.first(where: { $0.id == id }) { model.copyPassword(entry) }
        }
        .overlay {
            if entries.isEmpty {
                if !model.searchText.isEmpty {
                    ContentUnavailableView.search(text: model.searchText)
                } else if model.sidebarSelection == .favorites {
                    ContentUnavailableView("No Favorites", systemImage: "star",
                                           description: Text("Click the star on any item to add it here."))
                } else {
                    ContentUnavailableView("No Items", systemImage: "tray")
                }
            }
        }
        .navigationTitle(model.listTitle)
        .navigationSubtitle(entries.count == 1 ? "1 item" : "\(entries.count) items")
    }
}

/// Shared actions for context menus.
struct EntryActions: View {
    @Environment(AppModel.self) private var model
    let entry: KDBXEntry

    var body: some View {
        Button("Copy Password") { model.copyPassword(entry) }.disabled(entry.password.isEmpty)
        Button("Copy User Name") { model.copyUsername(entry) }.disabled(entry.username.isEmpty)
        if entry.totp != nil { Button("Copy Verification Code") { model.copyCode(entry) } }
        if !entry.url.isEmpty {
            Button("Copy Website") { model.copyURL(entry) }
            Button("Open Website") { model.openURL(entry) }.disabled(AppModel.webURL(entry.url) == nil)
        }
        Divider()
        Button(model.isFavorite(entry) ? "Remove from Favorites" : "Add to Favorites") { model.toggleFavorite(entry) }
    }
}

struct EntryRow: View {
    let entry: KDBXEntry
    let isFavorite: Bool

    var body: some View {
        HStack(spacing: 10) {
            EntryIcon(entry: entry, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.title.isEmpty ? "Untitled" : entry.title)
                    .lineLimit(1)
                Text(entry.username.isEmpty ? (displayHost(entry.url) ?? " ") : entry.username)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if entry.isExpired {
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.red).help("Expired")
            }
            if isFavorite {
                Image(systemName: "star.fill").font(.caption).foregroundStyle(.yellow)
            }
        }
        .padding(.vertical, 3)
    }
}

func displayHost(_ url: String) -> String? {
    guard let host = AppModel.webURL(url)?.host() else { return nil }
    return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
}

/// Custom KeePass icon if present, otherwise a coloured monogram.
struct EntryIcon: View {
    @Environment(AppModel.self) private var model
    let entry: KDBXEntry
    let size: CGFloat

    var body: some View {
        if let id = entry.customIconID, let data = model.database?.customIcons[id], let image = NSImage(data: data) {
            Image(nsImage: image)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: size * 0.8, height: size * 0.8)
                .frame(width: size, height: size)
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(color.gradient)
                .frame(width: size, height: size)
                .overlay {
                    Text(initial)
                        .font(.system(size: size * 0.48, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
        }
    }

    private var label: String { entry.title.isEmpty ? (displayHost(entry.url) ?? "?") : entry.title }

    private var initial: String { label.first.map { String($0).uppercased() } ?? "?" }

    private var color: Color {
        let palette: [Color] = [.blue, .indigo, .purple, .pink, .red, .orange, .teal, .green, .cyan, .brown, .mint]
        // Stable across launches (unlike `hashValue`).
        let hash = label.lowercased().unicodeScalars.reduce(UInt32(5381)) { ($0 << 5) &+ $0 &+ $1.value }
        return palette[Int(hash % UInt32(palette.count))]
    }
}
