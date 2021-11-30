from torch import nn


# Define neural network
class Network(nn.Module):
    def __init__(self, input_size, output_size):
        super(Network, self).__init__()

        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=3, out_channels=16, kernel_size=(3,), padding=1),  # output: 256 x 16
            nn.MaxPool1d(kernel_size=2),  # output: 128 x 16
            nn.ReLU()
        )

        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=16, out_channels=32, kernel_size=(3,), padding=1),  # output: 128 x 32
            nn.MaxPool1d(kernel_size=2),  # output: 64 x 32
            nn.ReLU()
        )

        self.conv3 = nn.Sequential(
            nn.Conv1d(in_channels=32, out_channels=64, kernel_size=(3,), padding=1),  # output: 64 x 64
            nn.MaxPool1d(kernel_size=2),  # output: 32 x 64
            nn.ReLU()
        )

        self.conv4 = nn.Sequential(
            nn.Conv1d(in_channels=64, out_channels=128, kernel_size=(3,), padding=1),  # output: 32 x 128
            nn.MaxPool1d(kernel_size=2),  # output: 16 x 128
            nn.ReLU()
        )

        # input: input_size / 2**4 * 128
        self.fully = nn.Linear(input_size * 8, output_size)

    def forward(self, x):
        o = self.conv1(x)
        o = self.conv2(o)
        o = self.conv3(o)
        o = self.conv4(o)
        o = o.view(x.size(0), -1)
        o = self.fully(o)
        return o
