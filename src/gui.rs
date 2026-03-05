use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Element, Length, Sandbox, Settings, Theme};
use std::path::PathBuf;
use std::process::Command;

pub fn main() -> iced::Result {
    OsintGui::run(Settings::default())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    IP,
    Domain,
    Username,
}

impl QueryType {
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                QueryType::IP => "IP Address",
                QueryType::Domain => "Domain",
                QueryType::Username => "Username",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    QueryTypeChanged(QueryType),
    InputChanged(String),
    SearchPressed,
    ClearOutput,
}

pub struct OsintGui {
    query_type: QueryType,
    input: String,
    output: String,
    is_loading: bool,
}


impl Sandbox for OsintGui {
    type Message = Message;

    fn new() -> Self {
        Self {
            query_type: QueryType::IP,
            input: String::new(),
            output: String::new(),
            is_loading: false,
        }
    }

    fn title(&self) -> String {
        String::from("OSINT Master - Hacker Edition")
    }

    fn theme(&self) -> Theme {
        Theme::Light
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::QueryTypeChanged(qt) => {
                self.query_type = qt;
            }
            Message::InputChanged(val) => {
                self.input = val;
            }
            Message::SearchPressed => {
                if !self.input.is_empty() {
                    self.is_loading = true;
                    self.output = "⏳ Processing your search...".to_string();
                    let result = execute_search(self.input.trim(), self.query_type);
                    self.output = result;
                    self.is_loading = false;
                }
            }
            Message::ClearOutput => {
                self.output.clear();
                self.input.clear();
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let title = text("OSINT Master")
            .size(28);
        let subtitle = text("Intelligence Gathering Tool")
            .size(14);


        let query_dropdown = row![
            button(text("IP").size(16))
                .padding(10)
                .on_press(Message::QueryTypeChanged(QueryType::IP))
                .style(if self.query_type == QueryType::IP {
                    iced::theme::Button::Primary
                } else {
                    iced::theme::Button::Secondary
                }),
            button(text("Domain").size(16))
                .padding(10)
                .on_press(Message::QueryTypeChanged(QueryType::Domain))
                .style(if self.query_type == QueryType::Domain {
                    iced::theme::Button::Primary
                } else {
                    iced::theme::Button::Secondary
                }),
            button(text("User").size(16))
                .padding(10)
                .on_press(Message::QueryTypeChanged(QueryType::Username))
                .style(if self.query_type == QueryType::Username {
                    iced::theme::Button::Primary
                } else {
                    iced::theme::Button::Secondary
                }),
        ]
        .spacing(12);

        let input_field = text_input(
            "Enter target...",
            &self.input,
        )
        .on_input(Message::InputChanged)
        .padding(12)
        .size(16)
        .width(Length::Fill)
        .style(iced::theme::TextInput::Default);

        let search_btn = button(text("🔍 Search").size(14))
            .padding(12)
            .on_press(Message::SearchPressed)
            .style(iced::theme::Button::Primary);

        let clear_btn = button(text("🗑️ Clear").size(14))
            .padding(12)
            .on_press(Message::ClearOutput)
            .style(iced::theme::Button::Secondary);

        let controls = row![query_dropdown, input_field, search_btn, clear_btn]
            .spacing(15)
            .padding(15)
            .align_items(Alignment::Center);

        let output_display = container(
            scrollable(
                text(&self.output)
                    .size(13)
            )
            .height(Length::Fill)
        )
        .padding(15)
        .height(Length::Fill)
        .width(Length::Fill);

        let header = container(
            column![
                title,
                subtitle,
                text("Intelligence Gathering Tool")
                    .size(12)
                    .font(iced::Font::MONOSPACE)
            ]
            .spacing(2)
        )
        .padding(20)
        .center_x()
        .width(Length::Fill);

        let content = column![
            header,
            controls,
            output_display
        ]
        .spacing(0)
        .height(Length::Fill)
        .width(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(iced::theme::Container::Box)
            .into()
    }
}

fn execute_search(target: &str, query_type: QueryType) -> String {
    let target = target.trim();
    if target.is_empty() {
        return "❌ Error: Please enter a target".to_string();
    }

    let cmd_path = get_osintmaster_path();
    let args = match query_type {
        QueryType::IP => vec!["ip", target],
        QueryType::Domain => vec!["domain", target],
        QueryType::Username => vec!["user", target],
    };

    match Command::new(&cmd_path).args(&args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() {
                if stdout.is_empty() {
                    "✅ Search completed successfully (no output)".to_string()
                } else {
                    stdout
                }
            } else {
                format!(
                    "❌ Error:\n{}",
                    if stderr.is_empty() { stdout } else { stderr }
                )
            }
        }
        Err(e) => {
            format!(
                "❌ Failed to execute osintmaster:\n{}\n\nMake sure 'osintmaster' binary is in PATH or same directory",
                e
            )
        }
    }
}

fn get_osintmaster_path() -> PathBuf {
    // Try current exe directory first
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent() {
            let candidate = dir.join("osintmaster");
            if candidate.exists() {
                return candidate;
            }
        }
    // Fall back to PATH
    PathBuf::from("osintmaster")
}
