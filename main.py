import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader 
import pandas as pd

from random import randint
from Preprocessor import extract_all_features

class NeuralNetwork(nn.Module):
    def __init__(self):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(47, 24),
            nn.Sigmoid(),
            nn.Linear(24, 24),
            nn.Sigmoid(),
            nn.Linear(24, 2)
        )
        self.softMax = nn.Softmax(dim=0)
    
    def forward(self, x):
        logits = self.network(x)
        return self.softMax(logits)

class URLDataset(Dataset):
    def __init__(self, dataframe):
        self.urls = dataframe["url"].to_numpy()
        self.labels = dataframe["status"].to_numpy()
        
    def __len__(self):
        return len(self.urls)
    
    def __getitem__(self, idx):
        url = self.urls[idx]
        label = self.labels[idx]

        label_tensor = torch.empty((1, 1))
        if label == "legitimate":
            label_tensor = torch.tensor([0, 1], dtype=torch.float)
        elif label == "phishing":
            label_tensor = torch.tensor([1, 0], dtype=torch.float)
            pass    
        return (
            torch.tensor(extract_all_features(url), dtype=torch.float),
            label_tensor
        )

def train(dataloader, model, loss_fn, optimizer):
    size = len(dataloader.dataset)
    model.train()
    for batch, (X, y) in enumerate(dataloader):
        pred = model(X)
        loss = loss_fn(pred, y)

        # Backpropagation
        loss.backward()
        optimizer.step()
        optimizer.zero_grad()

        if batch % 100 == 0:
            loss, current = loss.item(), (batch + 1) * len(X)
            print(f"loss: {loss:>7f}  [{current:>5d}/{size:>5d}]")

def test(dataloader, model, loss_fn):
    # actual size of the object
    size = len(dataloader.dataset)
    # (size // batch_size)
    num_batches = len(dataloader)
    # goes into eval mode  (black boxxxx)
    model.eval()
    test_loss, correct = 0, 0
    with torch.no_grad():
        for X, y in dataloader:
            pred = model(X)
            test_loss += loss_fn(pred, y).item()
            
            for current_batch in range(len(y)):
                total_count = 0
                for index in range(len(y[current_batch])):
                    threshold_value = 0.1
                    if pred[current_batch][index] == y[current_batch][index] or (pred[current_batch][index] - y[current_batch][index]) <= threshold_value:
                        total_count += 1
                if total_count == len(y[current_batch]):
                    correct += 1
                    print(pred[current_batch], y[current_batch])
    
    test_loss /= num_batches
    # this calculates the ratio of correct values
    print(correct, size)
    correct /= size
    print(f"Test Error: \n Accuracy: {(100*correct):>0.1f}%, Avg loss: {test_loss:>8f} \n")
    # print(f"Test Error: \n Avg loss: {test_loss:>8f} \n")


def train_model(trainingSet, testSet):
    batch_size = 32
    
    # Example usage with DataLoader
    training_dataloader = DataLoader(trainingSet, batch_size=batch_size)
    test_dataloader = DataLoader(testSet, batch_size=batch_size)

    model = NeuralNetwork()
    loss_fn = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.03)

    epochs = 10
    for t in range(epochs):
        print(f"Epoch {t+1}\n-------------------------------")
        train(training_dataloader, model, loss_fn, optimizer)
        test(test_dataloader, model, loss_fn)
    print("Done!")

    torch.save(model.state_dict(), "urlClassifier.pth")
    print("Saved PyTorch Model State to urlClassifier.pth")
    
    return model;
    

def test_model(model, trainingSet, testSet):
    for i in range(len(testSet)):
        x, y = testSet[i][0], testSet[i][1]   
        pred = model(x)
        print(pred, y)
    

def main():
    urlDf = pd.read_csv("data/URL/url_dataset.csv")
        
    legitmate_urls = urlDf[urlDf["status"] == "legitimate"]
    phishing_urls = urlDf[urlDf["status"] == "phishing"]

    midpoint = len(legitmate_urls) // 4

    legitmate_train = legitmate_urls.iloc[midpoint:]
    legitmate_test = legitmate_urls.iloc[:midpoint]

    phishing_train = phishing_urls.iloc[midpoint:]
    phishing_test = phishing_urls.iloc[:midpoint]    

    training_data = pd.concat([legitmate_train, phishing_train])
    training_data = training_data.sample(frac=1).reset_index(drop=True)
    trainingSet = URLDataset(training_data)

    test_data = pd.concat([legitmate_test, phishing_test])
    test_data = test_data.sample(frac=1).reset_index(drop=True) 
    testSet = URLDataset(test_data)
    
    model = train_model(trainingSet, testSet);
    test_model(model, trainingSet, testSet);
    # pass;
    
if __name__ == "__main__":
    main()
