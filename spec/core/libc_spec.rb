RSpec.describe NETSNMP::Core::C do
  it "exposes the free function" do
    expect(described_class).to respond_to(:free)
  end 
end
